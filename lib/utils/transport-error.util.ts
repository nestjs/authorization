import { ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import type { AuthorizationError } from '../errors/authorization.error.js';

type ErrorCtor = new (error: string | object) => Error;
const loaded = new Map<string, Promise<ErrorCtor | undefined>>();

/** Lazily loads an optional peer's exception class, once. */
function load(pkg: '@nestjs/websockets' | '@nestjs/microservices', name: string) {
  const key = `${pkg}#${name}`;
  let pending = loaded.get(key);
  if (!pending) {
    pending = import(pkg).then(
      (mod: Record<string, unknown>) => mod[name] as ErrorCtor,
      () => undefined,
    );
    loaded.set(key, pending);
  }

  return pending;
}

/**
 * The one place a denial becomes a response. `@Can()` (in the guard) and
 * `authorize()` (an `AuthorizationError` leaving a handler) both come here.
 * Every transport gets the body of Nest's own `UnauthorizedException` or
 * `ForbiddenException`, like any other 401 or 403:
 *
 * | Context | Error | Client sees |
 * | --- | --- | --- |
 * | `http`, `graphql` | `UnauthorizedException` / `ForbiddenException` | `{"message":"Forbidden","statusCode":403}`, or the `UNAUTHENTICATED` / `FORBIDDEN` code |
 * | `ws` | `WsException` | `{ status: 'error', message: 'Forbidden', statusCode: 403 }` |
 * | `rpc` | `RpcException` | `{ message: 'Forbidden', statusCode: 403 }` |
 *
 * The ws and rpc filters report `HttpException`s as "Internal server error",
 * hence their own classes, loaded only when those packages are installed.
 * The bodies never name the policy or the ability; `cause` does, for logs.
 */
export async function toTransportError(context: ExecutionContext, denial: AuthorizationError): Promise<Error> {
  const exception =
    denial.reason === 'unauthenticated'
      ? new UnauthorizedException(undefined, { cause: denial })
      : new ForbiddenException(undefined, { cause: denial });
  const body = exception.getResponse() as object;

  switch (context.getType<string>()) {
    case 'ws': {
      const WsException = await load('@nestjs/websockets', 'WsException');
      // `status: 'error'` is what the ws filter adds to string errors.
      if (WsException) {
        return withCause(new WsException({ status: 'error', ...body }), denial);
      }
      break;
    }
    case 'rpc': {
      const RpcException = await load('@nestjs/microservices', 'RpcException');
      if (RpcException) {
        return withCause(new RpcException(body), denial);
      }
      break;
    }
  }

  return exception;
}

function withCause(error: Error, cause: AuthorizationError): Error {
  error.cause = cause;
  return error;
}
