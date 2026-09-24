import { ConfigurableModuleBuilder, type Provider } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthorizationGuard } from './guards/authorization.guard.js';
import { AUTHORIZATION_MODULE_OPTIONS } from './authorization.constants.js';
import type { AuthorizationModuleExtras, AuthorizationModuleOptions } from './interfaces/authorization-module-options.interface.js';

const extras: AuthorizationModuleExtras = { isGlobal: true, globalGuard: true, policies: [], imports: [] };

/** @internal Resolves once `checkOptions()` accepted the runtime options, at startup. */
const CHECKED_OPTIONS = Symbol('AUTHORIZATION_CHECKED_OPTIONS');

export const { ConfigurableModuleClass, OPTIONS_TYPE, ASYNC_OPTIONS_TYPE } =
  new ConfigurableModuleBuilder<AuthorizationModuleOptions>({ optionsInjectionToken: AUTHORIZATION_MODULE_OPTIONS })
    .setClassMethodName('forRoot')
    .setFactoryMethodName('createAuthorizationOptions')
    .setExtras(extras, (definition, { isGlobal, globalGuard, policies = [], imports = [] }) => {
      const providers: Provider[] = [
        ...(definition.providers ?? []),
        ...policies,
        { provide: CHECKED_OPTIONS, inject: [AUTHORIZATION_MODULE_OPTIONS], useFactory: checkOptions },
      ];

      // `false` turns a default off; `undefined` (a wrapper forwarding an unset setting) keeps it.
      if (globalGuard !== false) {
        providers.push({ provide: APP_GUARD, useExisting: AuthorizationGuard });
      }

      return {
        ...definition,
        global: isGlobal !== false,
        // forRootAsync() already added its own `imports`; forRoot() passes them as an extra.
        imports: [...(definition.imports ?? []), ...imports],
        providers,
        exports: [...(definition.exports ?? []), ...policies],
      };
    })
    .build();

/**
 * What `forRootAsync()` takes: `useFactory` (with `inject` and `imports`),
 * `useClass` or `useExisting`, plus the structural options (`policies`,
 * `imports`, `globalGuard`, `isGlobal`) next to them.
 */
export type AuthorizationModuleAsyncOptions = typeof ASYNC_OPTIONS_TYPE;

/**
 * Fails the startup on runtime options that would be ignored or break at
 * request time: a structural option returned by the `forRootAsync()` factory,
 * or a `getUser` that is not a function. `forRoot()` never trips the first
 * check: the builder strips the structural options from its values.
 */
function checkOptions(options: AuthorizationModuleOptions | undefined): AuthorizationModuleOptions {
  const resolved: Record<string, unknown> = { ...options };
  for (const key of Object.keys(extras)) {
    if (resolved[key] !== undefined) {
      throw new Error(
        `AuthorizationModule: \`${key}\` is in the options the factory returned. It goes at the top level of ` +
          'forRootAsync(), next to useFactory, because it decides what the module registers.',
      );
    }
  }

  if (resolved.getUser !== undefined && typeof resolved.getUser !== 'function') {
    throw new Error(
      'AuthorizationModule: `getUser` must be a function that returns the current user (or a promise of it).',
    );
  }

  return resolved;
}
