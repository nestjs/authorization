import { Inject, Injectable, type CanActivate, type ExecutionContext } from '@nestjs/common';
import { AUTHORIZATION_GUARD, AUTHORIZATION_MODULE_OPTIONS, CAN_METADATA } from '../authorization.constants.js';
import { AuthorizationError } from '../errors/authorization.error.js';
import { AuthorizationEvents } from '../events/authorization-events.service.js';
import { defaultGetUser, toPolicyUser } from '../utils/get-user.util.js';
import { PolicyEvaluator } from '../services/policy-evaluator.service.js';
import { toTransportError } from '../utils/transport-error.util.js';
import type { AuthorizationModuleOptions } from '../interfaces/authorization-module-options.interface.js';
import type { CanRequirement } from '../interfaces/can-requirement.interface.js';

/**
 * Enforces `@Can()` requirements (class-level first, then method-level; all
 * must pass), each with the arguments its resolver reads from the call.
 * Handlers without `@Can()` pass through untouched. Whether a
 * route needs a user is authentication's business: with no user, policies
 * run with `null`, and a denial becomes 401 instead of 403.
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
    const requirements: CanRequirement[] = [
      ...(Reflect.getMetadata(CAN_METADATA, context.getClass()) ?? []),
      ...(Reflect.getMetadata(CAN_METADATA, context.getHandler()) ?? []),
    ];
    if (requirements.length === 0) {
      return true;
    }

    // A forRootAsync() factory may resolve to nothing: every option is optional.
    const user = toPolicyUser(await (this.options?.getUser ?? defaultGetUser)(context));
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
      if (decision === 'allow') {
        continue;
      }

      const handler = `${context.getClass().name}.${context.getHandler().name}`;
      this.events.emit({ type: 'denied', policy: policy.name, ability, reason: decision, user, args, handler });
      throw await toTransportError(context, new AuthorizationError(decision, policy.name, ability));
    }

    return true;
  }
}
