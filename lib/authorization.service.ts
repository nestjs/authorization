import { Injectable, type Type } from '@nestjs/common';
import { AuthorizationError } from './errors/authorization.error.js';
import { AuthorizationEvents } from './events/authorization-events.service.js';
import { toPolicyUser } from './utils/get-user.util.js';
import { PolicyEvaluator } from './services/policy-evaluator.service.js';
import type { Ability, AbilityArgs, UserArg } from './interfaces/ability.interface.js';

/**
 * Checks a policy ability. The policy is named explicitly, so the ability,
 * the user and every further argument are typed from the ability's own
 * signature, and the subject can be any shape (ORM rows, plain objects, DTOs).
 */
@Injectable()
export class AuthorizationService {
  constructor(
    private readonly evaluator: PolicyEvaluator,
    private readonly events: AuthorizationEvents,
  ) {}

  // In both checks, `const A` keeps the ability name a literal (`'update'`, not
  // `string`), so the user and the arguments are typed from that one ability.

  /**
   * Resolves to `true` when the ability allows, `false` otherwise, for
   * guests and signed-in users alike. Never throws on a denial, and emits
   * no event: use it to shape responses.
   */
  async can<P, const A extends Ability<P>>(
    policy: Type<P>,
    ability: A,
    user: UserArg<P, A>,
    ...args: AbilityArgs<P, A>
  ): Promise<boolean> {
    return (await this.evaluator.decide(policy, ability, user, args)) === 'allow';
  }

  /**
   * Like `can()`, but throws an `AuthorizationError` on denial, with reason
   * `unauthenticated` when there is no user and `forbidden` when there is
   * one. When it leaves a handler, the module turns it into the same 401 or
   * 403 as `@Can()` (or a `WsException`/`RpcException`).
   */
  async authorize<P, const A extends Ability<P>>(
    policy: Type<P>,
    ability: A,
    user: UserArg<P, A>,
    ...args: AbilityArgs<P, A>
  ): Promise<void> {
    const decision = await this.evaluator.decide(policy, ability, user, args);
    if (decision === 'allow') {
      return;
    }

    this.events.emit({ type: 'denied', policy: policy.name, ability, reason: decision, user: toPolicyUser(user), args });
    throw new AuthorizationError(decision, policy.name, ability);
  }
}
