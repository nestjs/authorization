export const POLICY_METADATA = 'authorization:policy';
export const CAN_METADATA = 'authorization:can';

/** Injection token of the runtime options (`forRoot()` values, or the `forRootAsync()` factory result). */
export const AUTHORIZATION_MODULE_OPTIONS = 'AUTHORIZATION_MODULE_OPTIONS';

/**
 * The static brand on `AuthorizationGuard`, which subclasses inherit. A
 * registry symbol, like `@nestjs/authentication`'s, so every copy of the
 * package (and any other package) recognizes the guard without importing it.
 */
export const AUTHORIZATION_GUARD = Symbol.for('@nestjs/authorization:guard');

/**
 * The static brand `@nestjs/authentication` puts on `AuthenticationGuard`,
 * which its subclasses inherit. A registry symbol, so it is recognized
 * without depending on that package.
 */
export const AUTHENTICATION_GUARD = Symbol.for('@nestjs/authentication:guard');

/**
 * Where `@nestjs/authentication` leaves, on a ws client and on GraphQL's
 * `context.req`, the function that answers with the user of one message or
 * operation: `carrier[AUTHENTICATION_USER_OF](context)`. Both outlive the
 * call: the client is the connection, and over graphql-ws `context.req` is
 * the socket's upgrade request. A registry symbol too, so it is found without
 * depending on that package.
 */
export const AUTHENTICATION_USER_OF = Symbol.for('nestjs.authentication.userOf');
