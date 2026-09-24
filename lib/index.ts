// Module
export { AuthorizationModule } from './authorization.module.js';
export type { AuthorizationModuleAsyncOptions } from './authorization.module-definition.js';
export { AUTHORIZATION_MODULE_OPTIONS } from './authorization.constants.js';
export type { AuthorizationModuleOptions, AuthorizationOptionsFactory } from './interfaces/index.js';

// Policies
export * from './decorators/index.js';
export type { Ability, PolicyBefore } from './interfaces/index.js';

// Checks: in services, on routes, and the user the route checks see
export { AuthorizationService } from './authorization.service.js';
export * from './guards/index.js';
export { defaultGetUser } from './utils/index.js';

// Denials: the error `authorize()` throws, and the events operators audit
// (also on the `nestjs:authorization:denied` diagnostics channel)
export { AuthorizationError } from './errors/index.js';
export { AuthorizationEvents, type AuthorizationDeniedEvent, type AuthorizationEvent } from './events/index.js';
