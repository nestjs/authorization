import { subscribe, unsubscribe } from 'node:diagnostics_channel';
import type { ExecutionContext } from '@nestjs/common';
import { Injectable, Logger } from '@nestjs/common';
import { DiscoveryService } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { MissingPolicyError } from '../lib/errors/missing-policy.error.js';
import {
  AuthorizationError,
  AuthorizationEvents,
  AuthorizationModule,
  AuthorizationService,
  defaultGetUser,
  Policy,
  type AuthorizationDeniedEvent,
  type PolicyBefore,
} from '../lib/index.js';
import { CommentPolicy, CommentsModule, DraftPolicy, PostPolicy, users, type Post, type User } from './fixtures.js';

const calls: unknown[][] = [];

@Policy()
class RecordingPolicy {
  before(user: User | null, ability: string, ...args: unknown[]) {
    calls.push([user, ability, ...args]);
    return undefined;
  }

  read(user: User | null) {
    return user !== null;
  }

  edit(user: User | null, doc: { ownerId: number }) {
    return user?.id === doc.ownerId;
  }

  truthy(_user: User | null) {
    return 1 as unknown as boolean;
  }
}

/**
 * Dereferences the user without a null check, as a policy does when the
 * compiler was talked out of it (a cast, `any`, a JavaScript policy).
 */
@Policy()
class CarelessPolicy {
  before(user: User | null) {
    if ((user as User).roles.includes('admin')) {
      return true;
    }
  }

  read(_user: User | null) {
    return true;
  }
}

@Policy()
class FlakyPolicy {
  read(_user: User | null): boolean {
    throw new Error('database is down');
  }
}

/** Asks a remote service (OPA, a feature-flag API) over fetch, which throws a TypeError when it's down. */
@Policy()
class RemotePolicy {
  async read(_user: User | null) {
    const response = await fetch('http://127.0.0.1:1/allow'); // nothing listens on port 1
    return response.ok;
  }
}

@Injectable()
class NotAPolicy {}

/** App-wide rules (Laravel's `Gate::before`) live in a base class that policies extend. */
abstract class AppPolicy implements PolicyBefore<User> {
  before(user: User | null) {
    if (user?.roles.includes('admin')) {
      return true;
    }
  }
}

@Policy()
class InvoicePolicy extends AppPolicy {
  void(_user: User | null) {
    return false;
  }
}

describe('AuthorizationService', () => {
  let authz: AuthorizationService;
  let events: AuthorizationEvents;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      // PostPolicy registered via forRoot; CommentPolicy discovered in CommentsModule.
      imports: [
        AuthorizationModule.forRoot({
          policies: [PostPolicy, RecordingPolicy, CarelessPolicy, FlakyPolicy, RemotePolicy, InvoicePolicy],
        }),
        CommentsModule,
      ],
    }).compile();
    await moduleRef.init();
    authz = moduleRef.get(AuthorizationService);
    events = moduleRef.get(AuthorizationEvents);
  });

  const post: Post = { id: 1, authorId: 1, title: 'x', published: false };

  it('checks plain-object subjects', async () => {
    expect(await authz.can(PostPolicy, 'update', users.alice, post)).toBe(true);
    expect(await authz.can(PostPolicy, 'update', users.bob, post)).toBe(false);
    await expect(authz.authorize(PostPolicy, 'update', users.bob, post)).rejects.toBeInstanceOf(AuthorizationError);
  });

  it('checks abilities without a subject', async () => {
    expect(await authz.can(PostPolicy, 'create', users.alice)).toBe(true);
    expect(await authz.can(PostPolicy, 'create', users.eve)).toBe(false);
  });

  it('awaits async abilities with injected dependencies', async () => {
    expect(await authz.can(CommentPolicy, 'create', users.alice)).toBe(true);
    expect(await authz.can(CommentPolicy, 'create', users.mallory)).toBe(false);
  });

  it('passes null (also for undefined) to the ability and to before()', async () => {
    calls.length = 0;
    expect(await authz.can(RecordingPolicy, 'read', undefined)).toBe(false);
    expect(await authz.can(RecordingPolicy, 'read', users.alice)).toBe(true);
    expect(calls).toEqual([
      [null, 'read'],
      [users.alice, 'read'],
    ]);
  });

  it('passes the ability arguments to before()', async () => {
    calls.length = 0;
    const doc = { ownerId: 1 };
    expect(await authz.can(RecordingPolicy, 'edit', users.alice, doc)).toBe(true);
    expect(calls).toEqual([[users.alice, 'edit', doc]]);
  });

  it('throws AuthorizationError: unauthenticated without a user, forbidden with one', async () => {
    const guest = await authz.authorize(PostPolicy, 'view', null, post).catch((e) => e);

    expect(guest).toBeInstanceOf(AuthorizationError);
    expect(guest).toBeInstanceOf(Error);
    expect(guest).toMatchObject({
      name: 'AuthorizationError',
      reason: 'unauthenticated',
      message: 'Unauthorized',
      policy: 'PostPolicy',
      ability: 'view',
    });

    const bob = await authz.authorize(PostPolicy, 'view', users.bob, post).catch((e) => e);
    expect(bob).toMatchObject({ reason: 'forbidden', message: 'Forbidden', policy: 'PostPolicy', ability: 'view' });

    await expect(authz.authorize(PostPolicy, 'view', null, { ...post, published: true })).resolves.toBeUndefined();
  });

  it("carries a 4xx `status`, so other packages (resilience's retries and circuit breaker) see a caller error", async () => {
    const guest = await authz.authorize(PostPolicy, 'view', null, post).catch((e) => e);
    const bob = await authz.authorize(PostPolicy, 'view', users.bob, post).catch((e) => e);
    expect(guest.status).toBe(401);
    expect(bob.status).toBe(403);
    // Not `statusCode`: Nest's BaseExceptionFilter answers any { statusCode, message } error with that status.
    expect(bob).not.toHaveProperty('statusCode');
  });

  describe('denial events', () => {
    const published: AuthorizationDeniedEvent[] = [];
    const emitted: AuthorizationDeniedEvent[] = [];
    const listener = (message: unknown) => published.push(message as AuthorizationDeniedEvent);
    beforeAll(() => {
      subscribe('nestjs:authorization:denied', listener);
      events.events$.subscribe((event) => emitted.push(event));
    });
    afterAll(() => unsubscribe('nestjs:authorization:denied', listener));
    beforeEach(() => {
      published.length = 0;
      emitted.length = 0;
    });

    it('emits each authorize() denial on events$ and the diagnostics channel, with the arguments', async () => {
      await authz.authorize(PostPolicy, 'view', users.bob, post).catch(() => undefined);
      await authz.authorize(PostPolicy, 'view', undefined, post).catch(() => undefined);
      const expected = [
        { type: 'denied', policy: 'PostPolicy', ability: 'view', reason: 'forbidden', user: users.bob, args: [post] },
        { type: 'denied', policy: 'PostPolicy', ability: 'view', reason: 'unauthenticated', user: null, args: [post] },
      ];

      expect(emitted).toEqual(expected);
      expect(published).toEqual(expected);
    });

    it('emits nothing for can(), or when authorize() allows', async () => {
      expect(await authz.can(PostPolicy, 'view', users.bob, post)).toBe(false);
      await authz.authorize(PostPolicy, 'view', users.alice, post);
      expect(emitted).toEqual([]);
      expect(published).toEqual([]);
    });
  });

  describe('a policy that throws for a guest', () => {
    const warn = vi.spyOn(Logger.prototype, 'warn');
    beforeEach(() => warn.mockReset().mockImplementation(() => undefined));
    afterAll(() => warn.mockRestore());

    it('denies (401) instead of failing with a 500, and warns once', async () => {
      await expect(authz.authorize(CarelessPolicy, 'read', null)).rejects.toMatchObject({
        reason: 'unauthenticated',
      });
      expect(await authz.can(CarelessPolicy, 'read', null)).toBe(false);
      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn.mock.calls[0][0]).toContain('CarelessPolicy.read threw for a guest');
    });

    it('still throws for signed-in users and for errors other than TypeError', async () => {
      await expect(authz.can(CarelessPolicy, 'read', { id: 7 } as unknown as User)).rejects.toBeInstanceOf(TypeError);
      await expect(authz.can(FlakyPolicy, 'read', null)).rejects.toThrow('database is down');
      expect(await authz.can(CarelessPolicy, 'read', users.root)).toBe(true);
    });

    it("lets an outage through for guests too, when the TypeError isn't about the null user", async () => {
      // fetch() reports a network failure as `TypeError: fetch failed`: a 500, not "sign in".
      await expect(authz.authorize(RemotePolicy, 'read', null)).rejects.toThrow(new TypeError('fetch failed'));
      await expect(authz.can(RemotePolicy, 'read', null)).rejects.toThrow('fetch failed');
      expect(warn).not.toHaveBeenCalled();
    });
  });

  it('runs a before() inherited from a base class', async () => {
    expect(await authz.can(InvoicePolicy, 'void', users.root)).toBe(true);
    expect(await authz.can(InvoicePolicy, 'void', users.alice)).toBe(false);
  });

  it('only allows on a literal true', async () => {
    expect(await authz.can(RecordingPolicy, 'truthy', users.alice)).toBe(false);
  });

  it('throws descriptive errors for unregistered policies and non-policies', async () => {
    await expect(authz.can(DraftPolicy, 'view', users.alice)).rejects.toThrow(
      new MissingPolicyError(
        'DraftPolicy is not registered. Add it to the providers of a module, or to AuthorizationModule.forRoot({ policies }).',
      ),
    );

    await expect(authz.can(NotAPolicy, 'x' as never, null as never)).rejects.toThrow(
      'NotAPolicy is not a policy. Decorate it with @Policy() and register it as a provider.',
    );
  });

  it('re-scans the providers for a missing policy (it may have been loaded lazily), not for a class that is no policy', async () => {
    const scans = vi.spyOn(DiscoveryService.prototype, 'getProviders');
    try {
      await expect(authz.can(NotAPolicy, 'x' as never, null as never)).rejects.toThrow(MissingPolicyError);
      expect(scans).not.toHaveBeenCalled();

      await expect(authz.can(DraftPolicy, 'view', users.alice)).rejects.toThrow(MissingPolicyError);
      expect(scans).toHaveBeenCalledTimes(1);
    } finally {
      scans.mockRestore();
    }
  });

  it('throws for an unknown ability', async () => {
    await expect(authz.can(PostPolicy, 'publish' as never, users.alice as never)).rejects.toThrow(
      "PostPolicy has no ability 'publish'.",
    );
  });

  it('does not take the methods every object inherits for abilities', async () => {
    // Reachable with a cast, or when an app passes an ability name it received.
    for (const name of ['toString', 'hasOwnProperty', 'valueOf', 'constructor', 'before']) {
      await expect(authz.can(PostPolicy, name as never, users.alice as never)).rejects.toThrow(
        `PostPolicy has no ability '${name}'.`,
      );
    }
  });
});

describe('defaultGetUser', () => {
  const ctx = (type: string, parts: Record<string, any>) =>
    ({
      getType: () => type,
      switchToHttp: () => ({ getRequest: () => parts.request }),
      switchToWs: () => ({ getClient: () => parts.client }),
      switchToRpc: () => ({ getContext: () => parts.rpcContext, getData: () => parts.data }),
      getArgByIndex: (i: number) => parts.args?.[i],
    }) as unknown as ExecutionContext;

  it('reads each transport', () => {
    expect(defaultGetUser(ctx('http', { request: { user: 'h' } }))).toBe('h');
    expect(defaultGetUser(ctx('ws', { client: { user: 'w' } }))).toBe('w');
    expect(defaultGetUser(ctx('ws', { client: { data: { user: 'sio' } } }))).toBe('sio');
    expect(defaultGetUser(ctx('rpc', { rpcContext: { user: 'c' }, data: {} }))).toBe('c');
    expect(defaultGetUser(ctx('graphql', { args: [{}, {}, { req: { user: 'g' } }] }))).toBe('g');
  });

  it('never reads the rpc payload, which the producer writes', () => {
    expect(defaultGetUser(ctx('rpc', { rpcContext: {}, data: { user: 'forged' } }))).toBeUndefined();
    expect(defaultGetUser(ctx('rpc', { rpcContext: { user: 'c' }, data: { user: 'forged' } }))).toBe('c');
  });

  it('keeps a null that authentication recorded (anonymous) instead of looking further', () => {
    expect(defaultGetUser(ctx('ws', { client: { user: null, data: { user: 'stale' } } }))).toBeNull();
    expect(defaultGetUser(ctx('rpc', { rpcContext: { user: null }, data: { user: 'forged' } }))).toBeNull();
  });
});
