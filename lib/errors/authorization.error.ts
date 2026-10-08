/** `unauthenticated`: denied with no user (401). `forbidden`: denied this user (403). */
export type DenialReason = 'unauthenticated' | 'forbidden';

/**
 * Thrown by `AuthorizationService.authorize()` when the ability denies.
 *
 * It is transport-agnostic, so a queue worker or a cron job catches it like
 * any other error. When it leaves a handler, AuthorizationModule turns it into
 * the transport's own error, the same one `@Can()` throws: 401/403 over HTTP
 * and GraphQL, a `WsException` in gateways, an `RpcException` in message
 * handlers.
 *
 * The message is only `Unauthorized` or `Forbidden`; `policy` and `ability`
 * say which check denied, for logs. Both are `null` when the guard denied a
 * handler that declares no check: no `@Can()`, `@Can.Anyone()` or
 * `@Public()`.
 */
export class AuthorizationError extends Error {
  /**
   * 401 (`unauthenticated`) or 403 (`forbidden`): the caller's fault, not an
   * outage, so other packages classify it without importing this class
   * (`@nestjs/resilience` neither retries it nor counts it against a
   * circuit breaker).
   */
  readonly status: 401 | 403;

  constructor(
    readonly reason: DenialReason,
    /** The policy class name, e.g. `OrderPolicy`; `null` for a handler that declares no check. */
    readonly policy: string | null,
    /** The ability that denied, e.g. `refund`; `null` for a handler that declares no check. */
    readonly ability: string | null,
  ) {
    super(reason === 'unauthenticated' ? 'Unauthorized' : 'Forbidden');
    this.name = 'AuthorizationError';
    this.status = reason === 'unauthenticated' ? 401 : 403;
  }
}
