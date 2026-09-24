import { Injectable } from '@nestjs/common';
import { POLICY_METADATA } from '../authorization.constants.js';
import type { GuestSafeBefore } from '../interfaces/policy-before.interface.js';

/**
 * Marks a class as a policy and makes it injectable. Every method returning
 * `boolean | Promise<boolean>` whose first parameter is the user is an
 * ability. The marker is what lets the module discover policies wherever
 * they are registered and validate `@Can()` references at bootstrap.
 *
 * A `before()` hook must accept a `null` user; `before(user: User)` does not
 * compile, with or without `implements PolicyBefore<User>`.
 *
 * @example
 * type Post = { id: number; authorId: number };
 *
 * @Policy()
 * export class PostPolicy {
 *   update(user: User, post: Post) { return post.authorId === user.id; }
 * }
 */
export function Policy(): <T extends Function>(target: T & GuestSafeBefore<T>) => void {
  return (target) => {
    Injectable()(target);
    Reflect.defineMetadata(POLICY_METADATA, true, target);
  };
}
