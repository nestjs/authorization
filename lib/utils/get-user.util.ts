import type { ExecutionContext } from '@nestjs/common';
import { AUTHENTICATION_USER_OF } from '../authorization.constants.js';

/**
 * @internal The user a policy sees: `null` for a guest. `undefined` (no user
 * set) and `false` (what Passport's optional authentication leaves on
 * `request.user` when there are no credentials) mean a guest too.
 */
export const toPolicyUser = (user: unknown): unknown => (user === undefined || user === false ? null : user);

/**
 * The default `getUser`: where `@nestjs/authentication`, Passport and most
 * auth guards leave the user.
 * - `http`: `request.user`
 * - `ws`: the user authentication recorded for this message, when it answers
 *   (below); else `client.user`, else `client.data.user` (socket.io's
 *   per-socket bag)
 * - `rpc`: `user` on the transport context (`ctx.switchToRpc().getContext()`),
 *   where an authentication guard or interceptor puts it. Never the message
 *   payload: whoever sends the message writes that.
 * - `graphql`: `context.req.user`, read from the resolver args positionally
 *   so this package needs no `@nestjs/graphql` dependency
 *
 * A `null` user is an answer (authentication ran, and the caller is
 * anonymous), so only `undefined` looks further.
 *
 * A ws client is the connection, not the message: `client.user` holds what
 * the last authenticated message left there, so a `@Public()` message, which
 * authenticates nothing, would be checked as that user, even after the
 * session was revoked. Authentication that records each message's user
 * leaves a function on the client, `client[Symbol.for('nestjs.authentication.userOf')]`:
 * called with the execution context, it returns this message's user, `null`
 * when the message is anonymous (a `@Public()` one is), or `undefined` when
 * it has no answer. `@nestjs/authentication` does.
 */
export function defaultGetUser(context: ExecutionContext): unknown {
  switch (context.getType<string>()) {
    case 'http':
      return context.switchToHttp().getRequest()?.user;
    case 'ws': {
      const client = context.switchToWs().getClient();
      const userOf = client?.[AUTHENTICATION_USER_OF];
      const own = typeof userOf === 'function' ? userOf.call(client, context) : undefined;
      if (own !== undefined) {
        return own;
      }
      return client?.user !== undefined ? client.user : client?.data?.user;
    }
    case 'rpc':
      return context.switchToRpc().getContext()?.user;
    case 'graphql':
      // Resolver args are (root, args, context, info).
      return context.getArgByIndex(2)?.req?.user;
    default:
      return undefined;
  }
}
