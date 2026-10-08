import { AUTHENTICATION_PUBLIC, CAN_ANYONE_METADATA, CAN_METADATA } from '../authorization.constants.js';
import type { CanRequirement } from '../interfaces/can-requirement.interface.js';

/** What a handler declares to the authorization guard. */
export interface RouteChecks {
  /**
   * `@Can()` of the class, then of the method: all must pass. A method's
   * `@Can.Anyone()` or `@Public()` lifts the class's, as a method's options
   * override the class's in `@nestjs/authentication`.
   */
  onClass: CanRequirement[];
  onMethod: CanRequirement[];
  /**
   * `@Can.Anyone()` on the class or the method, or `@Public()` from
   * `@nestjs/authentication`: with no `@Can()`, anyone may call it.
   */
  open: boolean;
}

export function routeChecks(type: Function, handler: Function): RouteChecks {
  // `@Authenticate()` records `false`, so a method reopened under a `@Public()` class is not public.
  const methodPublic = Reflect.getMetadata(AUTHENTICATION_PUBLIC, handler);
  const methodOpen = methodPublic === true || Reflect.getMetadata(CAN_ANYONE_METADATA, handler) === true;
  const classOpen =
    Reflect.getMetadata(CAN_ANYONE_METADATA, type) === true ||
    (methodPublic === undefined && Reflect.getMetadata(AUTHENTICATION_PUBLIC, type) === true);
  return {
    onClass: methodOpen ? [] : (Reflect.getMetadata(CAN_METADATA, type) ?? []),
    onMethod: Reflect.getMetadata(CAN_METADATA, handler) ?? [],
    open: methodOpen || classOpen,
  };
}
