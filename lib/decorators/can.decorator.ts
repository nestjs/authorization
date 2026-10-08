import type { Type } from '@nestjs/common';
import { CAN_ANYONE_METADATA, CAN_METADATA } from '../authorization.constants.js';
import type { CanAbility, CanArgs } from '../interfaces/ability.interface.js';
import type { CanRequirement } from '../interfaces/can-requirement.interface.js';

/**
 * Requires `policy[ability](user, ...args)` to return `true` before the
 * handler runs. Stackable; class-level and method-level requirements all
 * apply (AND), except that a method's `@Can.Anyone()` or `@Public()` lifts
 * the class's.
 *
 * The ability's user parameter must accept `null`. An ability that takes
 * arguments after the user needs `args`, which reads them from the call,
 * typed by the ability's own parameters. For `view(user: User | null,
 * workoutId: string)` on a `:workoutId` route:
 * `@Can(WorkoutPolicy, 'view', (context) => [context.switchToHttp().getRequest().params.workoutId])`.
 *
 * `args` runs in the guard, before pipes: route params are strings, and
 * nothing is validated yet. Pass identifiers and scopes, not records:
 * loading a record here loads it twice, and answers 403 before the handler
 * can answer 404. Record checks belong in `AuthorizationService`. An error
 * `args` throws (a `BadRequestException`, say) reaches the client as it is.
 *
 * A handler with no `@Can()`, no `@Can.Anyone()` and no `@Public()` from
 * `@nestjs/authentication` is denied.
 */
export function Can<P, const A extends CanAbility<P>>(
  policy: Type<P>,
  ability: A,
  ...resolver: CanArgs<P, A>
): ClassDecorator & MethodDecorator {
  const [args] = resolver;
  const requirement = { policy, ability, ...(args && { args }) } as CanRequirement;
  return (target: object, _key?: string | symbol, descriptor?: PropertyDescriptor) => {
    const host = descriptor ? descriptor.value : target;
    const existing: CanRequirement[] = Reflect.getMetadata(CAN_METADATA, host) ?? [];
    // Decorators apply bottom-up; prepend so metadata reads top-down.
    Reflect.defineMetadata(CAN_METADATA, [requirement, ...existing], host);
  };
}

/**
 * Lets anyone the handler admits call it, or every handler of the class:
 * whether that takes a signed-in user is authentication's business. For
 * routes that need no permission, such as the signed-in user's own profile,
 * and for those that check in the service, with `AuthorizationService`.
 *
 * On a method, it lifts the class's `@Can()`, as `@Public()` lifts the
 * class's `@Authenticate()`; a `@Can()` on the method itself still applies.
 * On a class, it lifts nothing: a method's `@Can()` still applies. A
 * `@Public()` route needs no `@Can.Anyone()`.
 */
Can.Anyone = (): ClassDecorator & MethodDecorator => {
  return (target: object, _key?: string | symbol, descriptor?: PropertyDescriptor) => {
    Reflect.defineMetadata(CAN_ANYONE_METADATA, true, descriptor ? descriptor.value : target);
  };
};
