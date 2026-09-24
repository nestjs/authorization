import { Injectable, type CallHandler, type ExecutionContext, type NestInterceptor } from '@nestjs/common';
import { catchError, from, mergeMap, throwError, type Observable } from 'rxjs';
import { AuthorizationError } from '../errors/authorization.error.js';
import { toTransportError } from '../utils/transport-error.util.js';

/**
 * Turns an `AuthorizationError` that leaves a handler (thrown by
 * `authorize()` in a service it called) into the transport's error, the same
 * one `@Can()` throws. Registered globally; other errors pass untouched.
 */
@Injectable()
export class AuthorizationErrorInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    return next.handle().pipe(
      catchError((error: unknown) =>
        error instanceof AuthorizationError
          ? from(toTransportError(context, error)).pipe(mergeMap((mapped) => throwError(() => mapped)))
          : throwError(() => error),
      ),
    );
  }
}
