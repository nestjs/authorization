import type { ExecutionContext, ModuleMetadata, Type } from '@nestjs/common';

/**
 * Runtime options: what `forRoot()` takes besides the structural options,
 * and what the `forRootAsync()` factory returns.
 */
export interface AuthorizationModuleOptions {
  /**
   * Reads the current user for `@Can()`. May return a promise. Defaults to
   * `defaultGetUser`, which reads `request.user` and its equivalents on the
   * other transports.
   */
  getUser?: (context: ExecutionContext) => unknown;
}

/** What a `forRootAsync({ useClass })` (or `useExisting`) class implements. */
export interface AuthorizationOptionsFactory {
  createAuthorizationOptions(): AuthorizationModuleOptions | Promise<AuthorizationModuleOptions>;
}

/**
 * Structural options, accepted at the top level of both `forRoot()` and
 * `forRootAsync()`: they decide what the module registers, so they cannot
 * come from the async factory.
 */
export interface AuthorizationModuleExtras {
  /** Register the module globally. Default `true`. */
  isGlobal?: boolean;
  /**
   * Register `AuthorizationGuard` as a global guard (`APP_GUARD`). Default
   * `true`. With `false`, apply it with `@UseGuards()`, after your
   * authentication guard.
   */
  globalGuard?: boolean;
  /**
   * Policies to register in the authorization module itself. Optional:
   * a `@Policy()` class registered as a provider of any module is found
   * without being listed.
   */
  policies?: Type<unknown>[];
  /**
   * Modules whose exported providers the `policies` inject. With
   * `forRootAsync()`, its `imports` serve the factory and the policies.
   */
  imports?: ModuleMetadata['imports'];
}
