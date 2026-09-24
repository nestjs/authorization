/**
 * Optional hook on a policy. Return `true`/`false` to decide, `undefined` to
 * fall through to the ability. Receives `null` when there is no user, so its
 * user parameter must accept `null`: `before(user: User)` is a compile error.
 *
 * Pass the policy's abilities as `TAbility` to type-check the ability names
 * `before()` compares against:
 *
 * @example
 * class OrderPolicy implements PolicyBefore<User, Ability<OrderPolicy>> {
 *   before(user: User | null, ability: Ability<OrderPolicy>) {
 *     if (ability !== 'refund' && user?.roles.includes('admin')) return true;
 *   }
 * }
 */
export interface PolicyBefore<TUser = unknown, TAbility extends string = string> {
  // A function-typed property, not a method: TypeScript checks method
  // parameters bivariantly, which would let `before(user: User)` through.
  before: (
    user: TUser | null,
    ability: TAbility,
    ...args: any[]
  ) => boolean | undefined | void | Promise<boolean | undefined | void>;
}

/**
 * What `@Policy()` accepts: any class, but if it has a `before()` hook, the
 * hook's user parameter must accept `null` (guests reach it too). Resolves to
 * `unknown` when the class is fine, and to an unsatisfiable shape whose key
 * explains the problem when it is not.
 */
export type GuestSafeBefore<T> = T extends abstract new (...args: any[]) => { before: infer B }
  ? B extends (user: null, ...args: any[]) => unknown
    ? unknown
    : { 'before() must accept a null user (guests reach it too): type it User | null': true }
  : unknown;
