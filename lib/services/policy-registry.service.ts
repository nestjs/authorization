import { Injectable, Logger, Scope, type OnModuleInit, type Type } from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants.js';
import { APP_GUARD, DiscoveryService, MetadataScanner, ModulesContainer } from '@nestjs/core';
import { AUTHENTICATION_GUARD, AUTHORIZATION_GUARD, CAN_METADATA, POLICY_METADATA } from '../authorization.constants.js';
import { MissingPolicyError } from '../errors/missing-policy.error.js';
import type { CanRequirement } from '../interfaces/can-requirement.interface.js';

type Wrapper = ReturnType<DiscoveryService['getProviders']>[number];

/** A guard registered with `APP_GUARD`: its class or instance, the module that registered it, and its scope. */
interface GlobalGuard {
  guard: unknown;
  module: string;
  requestScoped: boolean;
}

/** Guard class → how to move it ahead of AuthorizationGuard → the handlers affected. */
type Misordered = Map<Function, Map<string, string[]>>;

const isPolicy = (value: unknown): value is Type<unknown> =>
  typeof value === 'function' && !!Reflect.getMetadata(POLICY_METADATA, value);

/**
 * The ability `name` of a policy instance (or of the object that replaces it
 * in a test), or `undefined` when it has none. `before`, `constructor` and
 * the methods every object inherits (`toString`, `hasOwnProperty`) are not
 * abilities, whatever a cast or an ability name taken from input says.
 */
export function findAbility(instance: object, name: string): Function | undefined {
  if (name === 'before' || name === 'constructor') {
    return undefined;
  }
  const method = (instance as Record<string, unknown>)[name];
  if (typeof method !== 'function' || method === (Object.prototype as Record<string, unknown>)[name]) {
    return undefined;
  }
  return method;
}

/** A guard class (`@UseGuards()` metadata) or instance (`APP_GUARD`, `@UseGuards(new X())`). */
const guardClass = (guard: unknown): Function | undefined =>
  typeof guard === 'function' ? guard : (guard as object | null)?.constructor;

const isAuthorizationGuard = (guard: unknown) => !!(guardClass(guard) as any)?.[AUTHORIZATION_GUARD];

/** `@nestjs/authentication`'s `AuthenticationGuard` or a subclass: recognized by its brand, whatever its name. */
const isAuthenticationGuard = (guard: unknown) => (guardClass(guard) as any)?.[AUTHENTICATION_GUARD] === true;

/**
 * Names that mean authentication: `JwtAuthGuard`, Passport's `AuthGuard()`,
 * `OAuth2Guard`, `JwtGuard`, `ApiKeyGuard`. Not `Author`, `Authority`,
 * `Authz` or `Authorization`/`Authorisation`: those guards check permissions.
 */
const AUTHENTICATION_NAME = /auth(?!or|z)|jwt|api-?key/i;

/** Probably authenticates, going by the name. A guess, so it only logs. */
const looksLikeAuthentication = (guard: unknown) =>
  !isAuthorizationGuard(guard) &&
  !isAuthenticationGuard(guard) &&
  AUTHENTICATION_NAME.test(guardClass(guard)?.name ?? '');

const list = (wheres: string[]) =>
  wheres.length > 3 ? `${wheres.slice(0, 3).join(', ')} and ${wheres.length - 3} more` : wheres.join(', ');

/**
 * How to run `type` before AuthorizationGuard. `global` is the `APP_GUARD`
 * registration of the misplaced guard, if that is where it came from.
 */
function orderFix(type: Function, global: GlobalGuard | undefined, authorizationIsGlobal: boolean): string {
  if (global?.requestScoped) {
    return (
      'Nest runs request-scoped global guards after the singleton ones, whatever the import order: make ' +
      `${type.name} a singleton (a guard reads the request from its ExecutionContext), or set globalGuard: false ` +
      `and write @UseGuards(${type.name}, AuthorizationGuard).`
    );
  }
  if (global) {
    return `Nest runs global guards in module import order: import ${global.module} before AuthorizationModule.`;
  }
  return authorizationIsGlobal
    ? `Global guards run before @UseGuards(): set globalGuard: false and write @UseGuards(${type.name}, AuthorizationGuard).`
    : `@UseGuards() runs guards in the order listed: write @UseGuards(${type.name}, AuthorizationGuard).`;
}

/**
 * One message per misplaced guard and fix, naming the handlers affected.
 * `known`: the guard is `AuthenticationGuard` (by its brand), so the outcome
 * is certain; otherwise the name is a guess, and the message says so.
 */
function misorderMessages(misordered: Misordered, known: boolean): string[] {
  return [...misordered].flatMap(([type, fixes]) =>
    [...fixes].map(([fix, wheres]) => {
      const outcome = known
        ? `@Can() on ${list(wheres)} would see every caller as a guest.`
        : `if ${type.name} authenticates, @Can() on ${list(wheres)} sees every caller as a guest.`;
      return `AuthorizationGuard runs before ${type.name}, so ${outcome} ${fix}`;
    }),
  );
}

/** The metadata `@nestjs/graphql` puts on `@ResolveField()` methods. */
const GRAPHQL_FIELD_RESOLVER = 'graphql:resolve_property';
/** The injection token of `GraphQLModule`'s options. */
const GRAPHQL_MODULE_OPTIONS = 'GqlModuleOptions';

interface CanTarget {
  /** `ProductsController.create`. */
  where: string;
  /** The requirements that apply, each with where it was declared (class or method). */
  requirements: (CanRequirement & { declaredOn: string })[];
  /** `@UseGuards()` of the class, then of the method: the order Nest runs them in. */
  guards: unknown[];
  /** A GraphQL `@ResolveField()`, which runs guards only when GraphQLModule says so. */
  fieldResolver: boolean;
}

/**
 * Finds every `@Policy()` provider in the application, wherever it is
 * registered, and checks at startup that each `@Can()` can work.
 */
@Injectable()
export class PolicyRegistry implements OnModuleInit {
  private readonly logger = new Logger('Authorization');
  private policies?: Map<Function, object>;

  constructor(
    private readonly discovery: DiscoveryService,
    private readonly metadataScanner: MetadataScanner,
    private readonly modules: ModulesContainer,
  ) {}

  onModuleInit() {
    this.load();
    this.verifyCanUsage();
  }

  get<P>(policy: Type<P>): P {
    // A miss re-scans once: the policy may live in a lazily loaded module. A
    // class without @Policy() is never found, so a check that keeps naming one
    // does not walk every provider on every call.
    const instance = this.load().get(policy) ?? (isPolicy(policy) ? this.load(true).get(policy) : undefined);
    if (instance) {
      return instance as P;
    }
    throw new MissingPolicyError(this.whyMissing(policy));
  }

  /**
   * Keyed by the provider token, so `overrideProvider(OrderPolicy)` in a test
   * (`useValue`, `useClass`, `useFactory`) replaces what checks run against.
   */
  private load(refresh = false): Map<Function, object> {
    if (this.policies && !refresh) {
      return this.policies;
    }

    const policies = new Map<Function, object>();
    for (const wrapper of this.discovery.getProviders()) {
      const key = isPolicy(wrapper.token)
        ? wrapper.token
        : !wrapper.isFactory && isPolicy(wrapper.metatype)
          ? wrapper.metatype
          : undefined;
      if (!key || policies.has(key)) {
        continue; // same class registered in two modules: first wins
      }
      if (!wrapper.isDependencyTreeStatic() || wrapper.isTransient) {
        const why = wrapper.isTransient
          ? 'is transient'
          : wrapper.scope === Scope.REQUEST
            ? 'is request-scoped'
            : 'depends on a request-scoped provider';
        throw new Error(
          `${key.name} ${why}. Policies must be singletons: pass what varies per request to the ability as an argument.`,
        );
      }
      policies.set(key, wrapper.instance as object);
    }

    return (this.policies = policies);
  }

  private whyMissing(policy: Function) {
    return isPolicy(policy)
      ? `${policy.name} is not registered. Add it to the providers of a module, or to AuthorizationModule.forRoot({ policies }).`
      : `${policy.name} is not a policy. Decorate it with @Policy() and register it as a provider.`;
  }

  /**
   * Fails startup when a `@Can()` names a policy or an ability that does not
   * exist, sits on a GraphQL field resolver that GraphQL runs without guards,
   * or when `@nestjs/authentication`'s guard runs after the authorization
   * guard, so the policy would see every caller as a guest. Logs an error
   * when a `@Can()` is not enforced by any guard, or when another guard runs
   * after the authorization guard and looks like authentication: going by a
   * class name is a guess, so it does not fail.
   */
  private verifyCanUsage() {
    const targets = this.collectCanTargets();
    if (targets.length === 0) {
      return;
    }

    const policies = this.load();
    const globals = this.globalGuards();
    const globalGuards = globals.map(({ guard }) => guard);
    const guardsFieldResolvers = this.graphqlGuardsFieldResolvers();
    const missing = new Set<string>();
    const unguardedFields: string[] = [];
    const unenforced: string[] = [];
    const misordered: Misordered = new Map(); // AuthenticationGuard, by its brand: fails
    const suspected: Misordered = new Map(); // other guards, by their names: logs

    for (const { where, requirements, guards, fieldResolver } of targets) {
      for (const { policy, ability, declaredOn } of requirements) {
        const instance = policies.get(policy);
        const at = `@Can(${policy.name}, '${ability}') on ${declaredOn}`;
        if (!instance) {
          missing.add(`${at}: ${this.whyMissing(policy)}`);
        } else if (!findAbility(instance, ability)) {
          missing.add(`${at}: ${policy.name} has no ability '${ability}'.`);
        }
      }

      if (fieldResolver && guardsFieldResolvers === false) {
        // No guard runs here. A @Can() on the method would guard nothing; one on
        // the class guards the resolver's queries, like a class-level @UseGuards().
        for (const { policy, ability, declaredOn } of requirements) {
          if (declaredOn !== where) {
            continue;
          }
          unguardedFields.push(
            `@Can(${policy.name}, '${ability}') on ${where} is not enforced: GraphQL runs guards on field ` +
              `resolvers only with fieldResolverEnhancers: ['guards'] in the GraphQLModule options.`,
          );
        }
        continue;
      }

      // Nest runs global guards first, then the class's, then the method's.
      const chain = [...globalGuards, ...guards];
      const authz = chain.findIndex(isAuthorizationGuard);
      if (authz === -1) {
        unenforced.push(where);
        continue;
      }

      // Once an AuthenticationGuard has run, the user is set: another one after
      // AuthorizationGuard (a redundant @UseGuards()) changes nothing.
      const authenticated = chain.slice(0, authz).some(isAuthenticationGuard);

      for (let index = authz + 1; index < chain.length; index++) {
        const guard = chain[index];
        let found: Misordered | undefined;
        if (isAuthenticationGuard(guard)) {
          found = authenticated ? undefined : misordered;
        } else if (looksLikeAuthentication(guard)) {
          found = suspected;
        }
        if (!found) {
          continue;
        }

        const type = guardClass(guard)!;
        const fix = orderFix(type, globals[index], authz < globals.length);
        const fixes = found.get(type) ?? new Map<string, string[]>();
        fixes.set(fix, [...(fixes.get(fix) ?? []), where]);
        found.set(type, fixes);
      }
    }

    if (missing.size > 0) {
      throw new MissingPolicyError([...missing].join('\n'));
    }
    if (unguardedFields.length > 0) {
      throw new Error(unguardedFields.join('\n'));
    }
    if (misordered.size > 0) {
      throw new Error(misorderMessages(misordered, true).join('\n'));
    }
    if (unenforced.length > 0) {
      this.logger.error(
        `@Can() is not enforced on ${list(unenforced)}: AuthorizationModule has globalGuard: false, ` +
          `and these handlers have no @UseGuards(AuthorizationGuard).`,
      );
    }
    for (const message of misorderMessages(suspected, false)) {
      this.logger.error(message);
    }
  }

  /** Handlers of controllers and of class providers (resolvers, gateways) that `@Can()` applies to. */
  private collectCanTargets(): CanTarget[] {
    const targets: CanTarget[] = [];
    const seen = new Set<Function>();
    for (const wrapper of [...this.discovery.getControllers(), ...this.discovery.getProviders()]) {
      const type = classOf(wrapper);
      if (!type || seen.has(type)) {
        continue;
      }
      seen.add(type);

      const onClass: CanRequirement[] = Reflect.getMetadata(CAN_METADATA, type) ?? [];
      const classGuards: unknown[] = Reflect.getMetadata(GUARDS_METADATA, type) ?? [];

      for (const key of this.metadataScanner.getAllMethodNames(type.prototype)) {
        const method = type.prototype[key];
        const onMethod: CanRequirement[] = Reflect.getMetadata(CAN_METADATA, method) ?? [];
        // A class-level @Can() covers the handlers: decorated methods, not helpers.
        const covered = onClass.length > 0 && Reflect.getOwnMetadataKeys(method).length > 0;
        if (onMethod.length === 0 && !covered) {
          continue;
        }

        const where = `${type.name}.${key}`;
        targets.push({
          where,
          requirements: [
            ...onClass.map((requirement) => ({ ...requirement, declaredOn: type.name })),
            ...onMethod.map((requirement) => ({ ...requirement, declaredOn: where })),
          ],
          guards: [...classGuards, ...(Reflect.getMetadata(GUARDS_METADATA, method) ?? [])],
          fieldResolver: Reflect.getMetadata(GRAPHQL_FIELD_RESOLVER, method) === true,
        });
      }
    }

    return targets;
  }

  /**
   * Whether GraphQL runs guards on field resolvers (`fieldResolverEnhancers`
   * includes `'guards'`); `undefined` without a GraphQLModule. Read from its
   * options provider, so this package needs no `@nestjs/graphql` dependency.
   */
  private graphqlGuardsFieldResolvers(): boolean | undefined {
    const options = this.discovery.getProviders().find((wrapper) => wrapper.token === GRAPHQL_MODULE_OPTIONS)
      ?.instance as { fieldResolverEnhancers?: string[] } | undefined;
    if (!options) {
      return undefined;
    }
    return options.fieldResolverEnhancers?.includes('guards') ?? false;
  }

  /**
   * Guards registered with `APP_GUARD`, in the order Nest runs them: the
   * singletons in module scan order, then the request-scoped and transient
   * ones (declared with `scope`, which puts them among a module's injectables),
   * in scan order too. Guards added with `app.useGlobalGuards()` run between
   * the two groups and are not visible from inside the container.
   */
  private globalGuards(): GlobalGuard[] {
    const singletons: GlobalGuard[] = [];
    const requestScoped: GlobalGuard[] = [];

    for (const module of this.modules.values()) {
      const name = module.metatype.name;
      for (const wrapper of module.providers.values()) {
        if (wrapper.subtype === 'guard') {
          singletons.push({ guard: wrapper.instance, module: name, requestScoped: false });
        }
      }
      for (const wrapper of module.injectables.values()) {
        // `@UseGuards()` classes are injectables too; the scanner names an
        // `APP_GUARD` registration after its token. No instance exists outside
        // a request: the class (or its prototype) identifies the guard.
        if (wrapper.subtype === 'guard' && String(wrapper.token).startsWith(`${APP_GUARD} `)) {
          requestScoped.push({ guard: wrapper.instance ?? wrapper.metatype, module: name, requestScoped: true });
        }
      }
    }

    return [...singletons, ...requestScoped];
  }
}

function classOf(wrapper: Wrapper): Type<any> | undefined {
  const { metatype } = wrapper;
  if (typeof metatype !== 'function' || wrapper.isFactory || !metatype.prototype) {
    return undefined;
  }
  return metatype as Type<any>;
}
