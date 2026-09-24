import { Module, type DynamicModule } from '@nestjs/common';
import { APP_INTERCEPTOR, DiscoveryModule } from '@nestjs/core';
import { AuthorizationGuard } from './guards/authorization.guard.js';
import { AuthorizationErrorInterceptor } from './interceptors/authorization-error.interceptor.js';
import {
  ConfigurableModuleClass,
  type AuthorizationModuleAsyncOptions,
  type OPTIONS_TYPE,
} from './authorization.module-definition.js';
import { AuthorizationService } from './authorization.service.js';
import { AUTHORIZATION_MODULE_OPTIONS } from './authorization.constants.js';
import { AuthorizationEvents } from './events/authorization-events.service.js';
import { PolicyEvaluator } from './services/policy-evaluator.service.js';
import { PolicyRegistry } from './services/policy-registry.service.js';

/**
 * `AuthorizationModule.forRoot()` / `forRoot({...})` /
 * `forRootAsync({ imports, inject, useFactory | useClass | useExisting })`.
 *
 * Provides `AuthorizationService`, registers `AuthorizationGuard` globally
 * (it only acts on handlers with `@Can()`), and turns an `AuthorizationError`
 * leaving a handler into the transport's 401/403. Policies are found
 * wherever they are registered as providers.
 */
@Module({
  imports: [DiscoveryModule],
  providers: [
    PolicyRegistry,
    PolicyEvaluator,
    AuthorizationService,
    AuthorizationEvents,
    AuthorizationGuard,
    AuthorizationErrorInterceptor,
    { provide: APP_INTERCEPTOR, useExisting: AuthorizationErrorInterceptor },
  ],
  // PolicyEvaluator is exported so `@UseGuards(AuthorizationGuard)` resolves in any module.
  exports: [AuthorizationService, AuthorizationEvents, AuthorizationGuard, PolicyEvaluator, AUTHORIZATION_MODULE_OPTIONS],
})
export class AuthorizationModule extends ConfigurableModuleClass {
  static forRoot(options: typeof OPTIONS_TYPE = {}): DynamicModule {
    return super.forRoot(options);
  }

  static forRootAsync(options: AuthorizationModuleAsyncOptions): DynamicModule {
    return super.forRootAsync(options);
  }
}
