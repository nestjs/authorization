import type { DenialReason } from '../errors/authorization.error.js';

/**
 * `@Can()` or `authorize()` refused a caller. `can()` answering `false`
 * is not a denial: it shapes a response and refuses no one.
 *
 * Responses never name the policy or the ability, so this is where an
 * operator finds out which check refused whom.
 *
 * `user` and `args` are the objects the policy saw, as they are: log the
 * fields you need (the user's id, the record's id), not the whole event,
 * or whole user rows and records end up in your logs.
 */
export interface AuthorizationDeniedEvent {
  type: 'denied';
  /** The policy class name, e.g. `OrderPolicy`. */
  policy: string;
  /** The ability that denied, e.g. `refund`. */
  ability: string;
  /** `unauthenticated` (no user, 401) or `forbidden` (403). */
  reason: DenialReason;
  /** The user the policy saw; `null` for a guest. */
  user: unknown;
  /** The ability's arguments after the user, such as the record. Empty for `@Can()`. */
  args: readonly unknown[];
  /** The handler `@Can()` guarded, as `ClassName.methodName`. Absent for `authorize()`. */
  handler?: string;
}

/** Every event `AuthorizationEvents` emits. There is one kind so far: a denial. */
export type AuthorizationEvent = AuthorizationDeniedEvent;
