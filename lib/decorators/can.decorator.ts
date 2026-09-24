import type { Type } from '@nestjs/common';
import { CAN_METADATA } from '../authorization.constants.js';
import type { CanAbility } from '../interfaces/ability.interface.js';
import type { CanRequirement } from '../interfaces/can-requirement.interface.js';

/**
 * Requires `policy[ability](user)` to return `true` before the handler runs.
 * Stackable; class-level and method-level requirements all apply (AND).
 *
 * Only abilities callable with the user alone, and whose user parameter
 * accepts `null`, are accepted. Record-level checks belong in
 * `AuthorizationService`.
 */
export function Can<P>(policy: Type<P>, ability: CanAbility<P>): ClassDecorator & MethodDecorator {
  return (target: object, _key?: string | symbol, descriptor?: PropertyDescriptor) => {
    const host = descriptor ? descriptor.value : target;
    const existing: CanRequirement[] = Reflect.getMetadata(CAN_METADATA, host) ?? [];
    // Decorators apply bottom-up; prepend so metadata reads top-down.
    Reflect.defineMetadata(CAN_METADATA, [{ policy, ability }, ...existing], host);
  };
}
