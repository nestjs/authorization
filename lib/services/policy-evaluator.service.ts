import { Injectable, Logger, type Type } from '@nestjs/common';
import type { DenialReason } from '../errors/authorization.error.js';
import { toPolicyUser } from '../utils/get-user.util.js';
import { findAbility, PolicyRegistry } from './policy-registry.service.js';

export type Decision = 'allow' | DenialReason;

/**
 * A TypeError from using `null` as an object, which the engines word with
 * `null` in it: "Cannot read properties of null", "Cannot destructure
 * property 'id' of 'user' as it is null" (V8), "null is not an object"
 * (JavaScriptCore). Other TypeErrors, such as fetch's `TypeError: fetch
 * failed` when a service is down, are failures.
 */
const isNullDereference = (error: unknown): error is TypeError =>
  error instanceof TypeError && /\bnull\b/.test(error.message);

/**
 * Runs one check: `before()`, then the ability. Shared by the guard and
 * `AuthorizationService`; never throws on a denial.
 */
@Injectable()
export class PolicyEvaluator {
  private readonly logger = new Logger('Authorization');
  private readonly warnedGuestErrors = new Set<string>();

  constructor(private readonly registry: PolicyRegistry) {}

  async decide(policy: Type<unknown>, ability: string, user: unknown, args: unknown[]): Promise<Decision> {
    const instance = this.registry.get(policy) as object;
    const method = findAbility(instance, ability);
    if (!method) {
      throw new Error(`${policy.name} has no ability '${ability}'.`);
    }

    const current = toPolicyUser(user);
    let verdict: boolean;
    try {
      verdict = await this.evaluate(instance as Record<string, any>, method, ability, current, args);
    } catch (error) {
      // A guest reaching a hook or ability that dereferences the user (typed
      // `User` where `User | null` was due) fails closed with a 401 rather
      // than a 500. Any other error, or any error for a signed-in user, is a
      // real failure: an outage must not look like a denial.
      if (current !== null || !isNullDereference(error)) {
        throw error;
      }
      this.warnGuestError(policy, ability, error);
      return 'unauthenticated';
    }

    if (verdict) {
      return 'allow';
    }
    return current === null ? 'unauthenticated' : 'forbidden';
  }

  private warnGuestError(policy: Type<unknown>, ability: string, error: TypeError) {
    const key = `${policy.name}.${ability}`;
    if (this.warnedGuestErrors.has(key)) {
      return;
    }

    this.warnedGuestErrors.add(key);
    this.logger.warn(
      `${key} threw for a guest (${error.message}); treated as a denial. ` +
        `Type the user parameter of before() and of this ability as User | null.`,
    );
  }

  private async evaluate(
    instance: Record<string, any>,
    method: Function,
    ability: string,
    user: unknown,
    args: unknown[],
  ): Promise<boolean> {
    if (typeof instance.before === 'function') {
      const early = await instance.before(user, ability, ...args);
      if (early === true || early === false) {
        return early;
      }
    }
    // Only a literal `true` allows; truthy values do not.
    return (await method.call(instance, user, ...args)) === true;
  }
}
