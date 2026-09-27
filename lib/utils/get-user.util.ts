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
 * - `graphql`: the user authentication recorded for this operation, when it
 *   answers (below); else `context.req.user`, read from the resolver args
 *   positionally so this package needs no `@nestjs/graphql` dependency
 *
 * A `null` user is an answer (authentication ran, and the caller is
 * anonymous), so only `undefined` looks further.
 *
 * A ws client is the connection, not the message: `client.user` holds what
 * the last authenticated message left there, so a `@Public()` message, which
 * authenticates nothing, would be checked as that user, even after the
 * session was revoked. Over graphql-ws, `context.req` is the socket's upgrade
 * request, which every operation of the socket shares: the same goes for
 * `context.req.user`. Authentication that records each call's user leaves a
 * function on the client or the request, `[Symbol.for('nestjs.authentication.userOf')]`:
 * called with the execution context, it returns this call's user, `null`
 * when the call is anonymous (a `@Public()` one is), or `undefined` when it
 * has no answer. `@nestjs/authentication` does.
 */
export function defaultGetUser(context: ExecutionContext): unknown {
  switch (context.getType<string>()) {
    case 'http':
      return context.switchToHttp().getRequest()?.user;
    case 'ws': {
      const client = context.switchToWs().getClient();
      const own = recordedUser(client, context);
      if (own !== undefined) {
        return own;
      }
      return client?.user !== undefined ? client.user : client?.data?.user;
    }
    case 'rpc':
      return context.switchToRpc().getContext()?.user;
    case 'graphql': {
      // Resolver args are (root, args, context, info).
      const req = context.getArgByIndex(2)?.req;
      const own = recordedUser(req, context);
      return own !== undefined ? own : req?.user;
    }
    default:
      return undefined;
  }
}

/** What authentication answers for this call, through the function it left on `carrier`, if any. */
function recordedUser(carrier: any, context: ExecutionContext): unknown {
  const userOf = carrier?.[AUTHENTICATION_USER_OF];
  return typeof userOf === 'function' ? userOf.call(carrier, context) : undefined;
}
