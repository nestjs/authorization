/**
 * Type-level tests. The `@ts-expect-error` lines are verified by
 * `tsc --noEmit -p tsconfig.json`; if any of them stops being an error,
 * tsc fails with "Unused '@ts-expect-error' directive".
 */
import type { ExecutionContext } from '@nestjs/common';
import type { Ability, AuthorizationService, PolicyBefore } from '../lib/index.js';
import { AuthorizationModule, Can, Policy } from '../lib/index.js';
import { CommentPolicy, PostPolicy, users, type Post, type User } from './fixtures.js';

async function typeChecks(authz: AuthorizationService, maybeUser: User | null, post: Post) {
  // ---- Route level ------------------------------------------------------
  class Ok {
    @Can(PostPolicy, 'create') a() {}
    @Can(CommentPolicy, 'create') b() {}
  }
  class Typo {
    // @ts-expect-error misspelled ability
    @Can(PostPolicy, 'craete') a() {}
  }
  class NeedsRecord {
    // @ts-expect-error 'view' needs a Post: without a resolver, a route cannot provide it
    @Can(PostPolicy, 'view') a() {}
  }

  const workoutIdOf = (context: ExecutionContext) => [context.switchToHttp().getRequest().params.workoutId as string] as const;
  const untuple = (context: ExecutionContext) => [context.switchToHttp().getRequest().params.workoutId as string];
  // A resolver reads the arguments after the user, typed by the ability's own parameters.
  class WithArgs {
    @Can(WorkoutPolicy, 'view', (context) => [context.switchToHttp().getRequest().params.workoutId]) a() {}
    @Can(WorkoutPolicy, 'view', async () => ['w1']) b() {}
    @Can(WorkoutPolicy, 'logSet', () => ['w1', 3]) c() {}
    // Optional where every argument after the user is.
    @Can(WorkoutPolicy, 'list') d() {}
    @Can(WorkoutPolicy, 'list', () => [{ archived: true }]) e() {}
    // A resolver declared on its own infers an array: `as const` makes it the tuple.
    @Can(WorkoutPolicy, 'view', workoutIdOf) f() {}
  }
  class WrongArgs {
    // @ts-expect-error string[] may be empty: the ability needs exactly its workout id
    @Can(WorkoutPolicy, 'view', untuple) z() {}
    // @ts-expect-error the workout id is a string
    @Can(WorkoutPolicy, 'view', () => [1]) a() {}
    // @ts-expect-error logSet takes the reps too
    @Can(WorkoutPolicy, 'logSet', () => ['w1']) b() {}
    // @ts-expect-error view needs its workout id: no resolver, no id
    @Can(WorkoutPolicy, 'view') c() {}
    // @ts-expect-error list takes no workout id
    @Can(WorkoutPolicy, 'list', () => ['w1', 3]) d() {}
  }
  class GuestUnsafeWithArgs {
    // A resolver does not make an ability that rejects a guest usable on a route.
    // @ts-expect-error edit(user: User, ...) does not accept null
    @Can(WorkoutPolicy, 'edit', () => ['w1']) a() {}
  }
  class NotAnAbility {
    // @ts-expect-error helper methods that do not return boolean are not abilities
    @Can(PostPolicy, 'describe') a() {}
  }
  // @ts-expect-error before() is a hook, not an ability
  Can(PostPolicy, 'before');

  class GuestUnsafe {
    // A route may have no user, so its ability must accept null.
    // @ts-expect-error ability typed (user: User) cannot back @Can()
    @Can(StrictPolicy, 'publish') a() {}
  }

  // ---- Service ------------------------------------------------------------
  await authz.authorize(PostPolicy, 'update', users.alice, post);
  await authz.authorize(PostPolicy, 'create', users.alice);
  // @ts-expect-error misspelled ability
  await authz.authorize(PostPolicy, 'updaet', users.alice, post);
  // @ts-expect-error missing the post argument
  await authz.authorize(PostPolicy, 'update', users.alice);
  // @ts-expect-error wrong subject shape
  await authz.authorize(PostPolicy, 'update', users.alice, { id: 1 });
  // @ts-expect-error too many arguments
  await authz.authorize(PostPolicy, 'create', users.alice, post);

  // Null users: allowed where the ability accepts them...
  await authz.authorize(PostPolicy, 'view', maybeUser, post);
  await authz.authorize(PostPolicy, 'view', undefined, post);
  // ...and a compile error where it does not, so the caller narrows first.
  // @ts-expect-error update(user: User, ...) does not accept null
  await authz.authorize(PostPolicy, 'update', maybeUser, post);
  if (maybeUser) {
    await authz.authorize(PostPolicy, 'update', maybeUser, post);
  }

  class NoRouteAbilities {
    // @ts-expect-error no ability of StrictPolicy works in @Can()
    @Can(StrictPolicy, 'publish') a() {}
  }

  // The untyped decision engine is not part of the service's API.
  // @ts-expect-error decide() is internal
  authz.decide;

  return [Ok, Typo, NeedsRecord, WithArgs, WrongArgs, GuestUnsafeWithArgs, NotAnAbility, GuestUnsafe, NoRouteAbilities];
}

// ---- before() must accept a guest ---------------------------------------

class GuestUnsafeBefore implements PolicyBefore<User> {
  // @ts-expect-error guests reach before() as null; `User` alone is rejected
  before(user: User) {
    return user.roles.includes('admin');
  }
}

// Caught by @Policy() too, without an `implements` clause.
// @ts-expect-error before() must accept a null user
@Policy()
class GuestUnsafeBeforeUndeclared {
  before(user: User) {
    return user.roles.includes('admin');
  }
  view(_user: User | null) {
    return true;
  }
}

@Policy()
class GuestSafeBefore implements PolicyBefore<User> {
  before(user: User | null) {
    if (user?.roles.includes('admin')) {
      return true;
    }
  }
  view(_user: User | null) {
    return true;
  }
}

// Typed ability names in before(): a misspelled exclusion does not compile.
@Policy()
class TypedActions implements PolicyBefore<User, Ability<TypedActions>> {
  before(user: User | null, action: Ability<TypedActions>) {
    // @ts-expect-error 'refnd' is not an ability of TypedActions
    if (action === 'refnd') {
      return undefined;
    }
    if (action !== 'refund' && user?.roles.includes('admin')) {
      return true;
    }
  }
  view(_user: User | null) {
    return true;
  }
  refund(_user: User | null, _amount: number) {
    return false;
  }
}

export const beforeFixtures = [GuestUnsafeBefore, GuestUnsafeBeforeUndeclared, GuestSafeBefore, TypedActions];

// ---- Module registration ---------------------------------------------------

// Structural options sit at the top level of forRootAsync(), next to the factory...
AuthorizationModule.forRootAsync({
  useFactory: () => ({ getUser: () => users.alice }),
  policies: [PostPolicy],
  globalGuard: false,
  isGlobal: true,
});
// ...never in the factory's result: providers must be known when the module is defined.
// @ts-expect-error '{ policies: ... }' is not assignable to 'AuthorizationModuleOptions'
AuthorizationModule.forRootAsync({ useFactory: () => ({ policies: [PostPolicy] }) });
AuthorizationModule.forRoot({ policies: [PostPolicy], getUser: async () => users.alice });

class StrictPolicy {
  publish(user: User) {
    return user.roles.includes('editor');
  }
}

class WorkoutPolicy {
  list(_user: User | null, _filter?: { archived: boolean }) {
    return true;
  }
  view(user: User | null, workoutId: string) {
    return !!user && workoutId !== '';
  }
  logSet(user: User | null, workoutId: string, reps: number) {
    return !!user && workoutId !== '' && reps > 0;
  }
  edit(user: User, workoutId: string) {
    return user.id > 0 && workoutId !== '';
  }
}

it('type checks are enforced by tsc', () => {
  expect(typeof typeChecks).toBe('function');
});
