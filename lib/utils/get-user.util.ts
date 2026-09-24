import type { ExecutionContext } from '@nestjs/common';

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
 * - `ws`: `client.user`, else `client.data.user` (socket.io's per-socket bag)
 * - `rpc`: `user` on the transport context (`ctx.switchToRpc().getContext()`),
 *   where an authentication guard or interceptor puts it. Never the message
 *   payload: whoever sends the message writes that.
 * - `graphql`: `context.req.user`, read from the resolver args positionally
 *   so this package needs no `@nestjs/graphql` dependency
 *
 * A `null` user is an answer (authentication ran, and the caller is
 * anonymous), so only `undefined` looks further.
 */
export function defaultGetUser(context: ExecutionContext): unknown {
  switch (context.getType<string>()) {
    case 'http':
      return context.switchToHttp().getRequest()?.user;
    case 'ws': {
      const client = context.switchToWs().getClient();
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
