import { Inject, Injectable, type CanActivate, type ExecutionContext } from '@nestjs/common';
import { AUTHORIZATION_GUARD, AUTHORIZATION_MODULE_OPTIONS } from '../authorization.constants.js';
import { AuthorizationError, type DenialReason } from '../errors/authorization.error.js';
import { AuthorizationEvents } from '../events/authorization-events.service.js';
import { defaultGetUser, toPolicyUser } from '../utils/get-user.util.js';
import { routeChecks } from '../utils/route-checks.util.js';
import { PolicyEvaluator } from '../services/policy-evaluator.service.js';
import { toTransportError } from '../utils/transport-error.util.js';
import type { AuthorizationModuleOptions } from '../interfaces/authorization-module-options.interface.js';

/**
 * Enforces `@Can()` requirements (class-level first, then method-level; all
 * must pass; a method's `@Can.Anyone()` or `@Public()` lifts the class's),
 * each with the arguments its resolver reads from the call. Denies by
 * default: a handler with no `@Can()` runs only when it, or its class, has
 * `@Can.Anyone()` or `@nestjs/authentication`'s `@Public()`. Whether a route
 * needs a user is authentication's business: with no user, policies run with
 * `null`, and a denial becomes 401 instead of 403.
 *
 * Registered globally by default. With `globalGuard: false`, list it after
 * your authentication guard: `@UseGuards(JwtAuthGuard, AuthorizationGuard)`.
 */
@Injectable()
export class AuthorizationGuard implements CanActivate {
  static readonly [AUTHORIZATION_GUARD] = true;

  constructor(
    private readonly evaluator: PolicyEvaluator,
    private readonly events: AuthorizationEvents,
    @Inject(AUTHORIZATION_MODULE_OPTIONS) private readonly options: AuthorizationModuleOptions,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const { onClass, onMethod, open } = routeChecks(context.getClass(), context.getHandler());
    const requirements = [...onClass, ...onMethod];
    if (requirements.length === 0 && open) {
      return true;
    }

    // A forRootAsync() factory may resolve to nothing: every option is optional.
    const user = toPolicyUser(await (this.options?.getUser ?? defaultGetUser)(context));
    if (requirements.length === 0) {
      // Declares no check: a forgotten @Can() must not open the route.
      return this.deny(context, user === null ? 'unauthenticated' : 'forbidden', user, null, null, []);
    }

    for (const { policy, ability, args: resolve } of requirements) {
      // Resolved per requirement, in order: once one denies, later resolvers do not run.
      const args = resolve ? await resolve(context) : [];
      if (!Array.isArray(args)) {
        throw new TypeError(
          `The args of @Can(${policy.name}, '${ability}') must return an array: ` +
            `the ability's arguments after the user.`,
        );
      }
      const decision = await this.evaluator.decide(policy, ability, user, args);
      if (decision !== 'allow') {
        return this.deny(context, decision, user, policy.name, ability, args);
      }
    }

    return true;
  }

  private async deny(
    context: ExecutionContext,
    reason: DenialReason,
    user: unknown,
    policy: string | null,
    ability: string | null,
    args: readonly unknown[],
  ): Promise<never> {
    const handler = `${context.getClass().name}.${context.getHandler().name}`;
    this.events.emit({ type: 'denied', policy, ability, reason, user, args, handler });
    throw await toTransportError(context, new AuthorizationError(reason, policy, ability));
  }
}
