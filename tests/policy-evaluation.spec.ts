import { Injectable, Logger, Module } from '@nestjs/common';
import { INJECTABLE_WATERMARK } from '@nestjs/common/constants.js';
import { Test, type TestingModule } from '@nestjs/testing';
import { CAN_METADATA, POLICY_METADATA } from '../lib/authorization.constants.js';
import {
  AuthorizationError,
  AuthorizationEvents,
  AuthorizationModule,
  AuthorizationService,
  Can,
  Policy,
  type AuthorizationDeniedEvent,
} from '../lib/index.js';
import { PostPolicy, users, type User } from './fixtures.js';

const trace: string[] = [];

/** `before()` answers from a lookup table keyed by ability, so each case picks its verdict. */
const verdicts: Record<string, unknown> = {};

@Policy()
class HookPolicy {
  async before(_user: User | null, ability: string) {
    trace.push(`before:${ability}`);
    return verdicts[ability] as boolean | undefined;
  }

  allow(_user: User | null) {
    trace.push('allow');
    return true;
  }

  deny(_user: User | null) {
    trace.push('deny');
    return false;
  }
}

@Policy()
class ValuePolicy {
  async asyncTrue(_user: User | null) {
    return true;
  }

  async asyncTruthy(_user: User | null) {
    return 'yes' as unknown as boolean;
  }

  asyncFalse(_user: User | null) {
    return Promise.resolve(false);
  }

  returnsNothing(_user: User | null) {
    return undefined as unknown as boolean;
  }

  // An arrow-function property is still an ability: it is a function on the instance.
  byProperty = (user: User | null) => user !== null;
}

/** Dereferences the user in the ability itself, not in before(). */
@Policy()
class DereferencingPolicy {
  own(user: User | null, doc: { ownerId: number }) {
    return (user as User).id === doc.ownerId;
  }

  destructure(user: User | null) {
    const { roles } = user as User;
    return roles.includes('writer');
  }

  rejects(_user: User | null): Promise<boolean> {
    return Promise.reject(new TypeError("Cannot read properties of null (reading 'id')"));
  }

  unrelated(_user: User | null): boolean {
    throw new TypeError('Invalid URL');
  }
}

@Policy()
class TokenPolicy {
  read(user: User | null) {
    return user?.roles.includes('reader') ?? false;
  }
}

describe('policy evaluation', () => {
  let moduleRef: TestingModule;
  let authz: AuthorizationService;
  const denials: AuthorizationDeniedEvent[] = [];

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      imports: [AuthorizationModule.forRoot({ policies: [PostPolicy, HookPolicy, ValuePolicy, DereferencingPolicy] })],
    }).compile();
    await moduleRef.init();
    authz = moduleRef.get(AuthorizationService);
    moduleRef.get(AuthorizationEvents).events$.subscribe((event) => denials.push(event));
  });
  afterAll(() => moduleRef.close());
  beforeEach(() => {
    trace.length = 0;
    denials.length = 0;
    for (const key of Object.keys(verdicts)) {
      delete verdicts[key];
    }
  });

  describe('before()', () => {
    it('decides alone when it returns true or false, without calling the ability', async () => {
      verdicts.deny = true;
      verdicts.allow = false;

      expect(await authz.can(HookPolicy, 'deny', users.alice)).toBe(true);
      expect(await authz.can(HookPolicy, 'allow', users.alice)).toBe(false);
      expect(trace).toEqual(['before:deny', 'before:allow']);
    });

    it('falls through to the ability on undefined and on any value that is not a boolean', async () => {
      for (const value of [undefined, null, 1, 0, 'true', {}]) {
        verdicts.deny = value;
        trace.length = 0;

        expect(await authz.can(HookPolicy, 'deny', users.alice)).toBe(false);
        expect(trace).toEqual(['before:deny', 'deny']);
      }
    });

    it('denies a guest with 401 when it returns false, and a user with 403', async () => {
      verdicts.allow = false;

      await expect(authz.authorize(HookPolicy, 'allow', null)).rejects.toMatchObject({ reason: 'unauthenticated', status: 401 });
      await expect(authz.authorize(HookPolicy, 'allow', users.alice)).rejects.toMatchObject({ reason: 'forbidden', status: 403 });
    });
  });

  describe('ability results', () => {
    it('awaits a promise and allows only when it resolves to a literal true', async () => {
      expect(await authz.can(ValuePolicy, 'asyncTrue', null)).toBe(true);
      expect(await authz.can(ValuePolicy, 'asyncTruthy', users.alice)).toBe(false);
      expect(await authz.can(ValuePolicy, 'asyncFalse', users.alice)).toBe(false);
      expect(await authz.can(ValuePolicy, 'returnsNothing', users.alice)).toBe(false);
    });

    it('treats a function-valued property as an ability', async () => {
      expect(await authz.can(ValuePolicy, 'byProperty', users.alice)).toBe(true);
      expect(await authz.can(ValuePolicy, 'byProperty', null)).toBe(false);
    });

    it('passes false (Passport, no credentials) on to the policy as null, and reports it as a guest', async () => {
      await expect(authz.authorize(ValuePolicy, 'byProperty', false as never)).rejects.toMatchObject({
        reason: 'unauthenticated',
      });
      expect(denials).toEqual([
        { type: 'denied', policy: 'ValuePolicy', ability: 'byProperty', reason: 'unauthenticated', user: null, args: [] },
      ]);
    });

    it('keeps falsy users that are not undefined or false (0, empty string) as signed in', async () => {
      await expect(authz.authorize(ValuePolicy, 'asyncFalse', 0 as never)).rejects.toMatchObject({ reason: 'forbidden' });
      await expect(authz.authorize(ValuePolicy, 'asyncFalse', '' as never)).rejects.toMatchObject({ reason: 'forbidden' });
    });
  });

  describe('a guest reaching an ability that dereferences the user', () => {
    const warn = vi.spyOn(Logger.prototype, 'warn');
    beforeEach(() => warn.mockReset().mockImplementation(() => undefined));
    afterAll(() => warn.mockRestore());

    it('fails closed with 401 for a property read, a destructuring and a rejected promise', async () => {
      for (const ability of ['destructure', 'rejects'] as const) {
        await expect(authz.authorize(DereferencingPolicy, ability, null)).rejects.toMatchObject({
          reason: 'unauthenticated',
          ability,
        });
      }
      await expect(authz.authorize(DereferencingPolicy, 'own', null, { ownerId: 1 })).rejects.toMatchObject({
        reason: 'unauthenticated',
      });
    });

    it('warns once per policy and ability, naming each', async () => {
      // A fresh app: the evaluator remembers what it warned about.
      const fresh = await Test.createTestingModule({
        imports: [AuthorizationModule.forRoot({ policies: [DereferencingPolicy] })],
      }).compile();
      await fresh.init();
      const service = fresh.get(AuthorizationService);

      await service.can(DereferencingPolicy, 'own', null, { ownerId: 1 });
      await service.can(DereferencingPolicy, 'own', null, { ownerId: 2 });
      await service.can(DereferencingPolicy, 'destructure', null);
      await service.can(DereferencingPolicy, 'destructure', null);
      await fresh.close();

      const messages = warn.mock.calls.map(([message]) => String(message));
      expect(messages).toHaveLength(2);
      expect(messages[0]).toMatch(/^DereferencingPolicy\.own threw for a guest \(.*null.*\); treated as a denial\. /);
      expect(messages[1]).toMatch(/^DereferencingPolicy\.destructure threw for a guest /);
      expect(messages[1]).toContain('Type the user parameter of before() and of this ability as User | null.');
    });

    it('lets a TypeError that does not mention null through, as a failure', async () => {
      await expect(authz.can(DereferencingPolicy, 'unrelated', null)).rejects.toThrow(new TypeError('Invalid URL'));
      expect(warn).not.toHaveBeenCalled();
    });

    it('lets the same TypeError through for a signed-in user', async () => {
      await expect(authz.can(DereferencingPolicy, 'rejects', users.alice)).rejects.toBeInstanceOf(TypeError);
    });
  });

  it('keeps concurrent checks for different users apart', async () => {
    const post = { id: 1, authorId: 1, title: 'x', published: false };
    const checks = Object.values(users).map((user) => authz.can(PostPolicy, 'update', user, post));

    expect(await Promise.all(checks)).toEqual(Object.values(users).map((user) => user.id === 1 || user.roles.includes('admin')));
  });

  it('emits one event per denial, in order, for concurrent authorize() calls', async () => {
    const post = { id: 2, authorId: 2, title: 'x', published: false };
    await Promise.allSettled([
      authz.authorize(PostPolicy, 'view', users.alice, post),
      authz.authorize(PostPolicy, 'view', users.bob, post),
      authz.authorize(PostPolicy, 'view', null, post),
    ]);

    expect(denials.map(({ user, reason }) => ({ user, reason }))).toEqual([
      { user: users.alice, reason: 'forbidden' },
      { user: null, reason: 'unauthenticated' },
    ]);
  });
});

describe('policies registered under another token', () => {
  it('finds a @Policy() class provided with useClass under a string token by its class', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AuthorizationModule.forRoot()],
      providers: [{ provide: 'TOKEN_POLICY', useClass: TokenPolicy }],
    }).compile();
    await moduleRef.init();

    const authz = moduleRef.get(AuthorizationService);
    expect(await authz.can(TokenPolicy, 'read', { id: 1, roles: ['reader'] })).toBe(true);
    expect(await authz.can(TokenPolicy, 'read', users.alice)).toBe(false);
    await moduleRef.close();
  });

  it('finds a policy provided with a factory under its own class token', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AuthorizationModule.forRoot()],
      providers: [{ provide: TokenPolicy, useFactory: () => ({ read: () => true }) }],
    }).compile();
    await moduleRef.init();

    expect(await moduleRef.get(AuthorizationService).can(TokenPolicy, 'read', null)).toBe(true);
    await moduleRef.close();
  });

  it('uses the first registration when two modules provide the same policy', async () => {
    @Module({ providers: [TokenPolicy] })
    class FirstModule {}

    @Module({ providers: [TokenPolicy] })
    class SecondModule {}

    const moduleRef = await Test.createTestingModule({
      imports: [AuthorizationModule.forRoot(), FirstModule, SecondModule],
    }).compile();
    await moduleRef.init();

    expect(await moduleRef.get(AuthorizationService).can(TokenPolicy, 'read', { id: 1, roles: ['reader'] })).toBe(true);
    await moduleRef.close();
  });
});

describe('AuthorizationError', () => {
  it('maps unauthenticated to 401 Unauthorized and forbidden to 403 Forbidden', () => {
    const guest = new AuthorizationError('unauthenticated', 'OrderPolicy', 'refund');
    const user = new AuthorizationError('forbidden', 'OrderPolicy', 'refund');

    expect(guest).toMatchObject({ name: 'AuthorizationError', message: 'Unauthorized', status: 401, reason: 'unauthenticated' });
    expect(user).toMatchObject({ name: 'AuthorizationError', message: 'Forbidden', status: 403, reason: 'forbidden' });
  });

  it('keeps the policy and ability out of the message and in their own fields', () => {
    const error = new AuthorizationError('forbidden', 'OrderPolicy', 'refund');

    expect(error.message).not.toMatch(/OrderPolicy|refund/);
    expect({ policy: error.policy, ability: error.ability }).toEqual({ policy: 'OrderPolicy', ability: 'refund' });
    expect(String(error)).toBe('AuthorizationError: Forbidden');
    expect(error.stack).toContain('AuthorizationError: Forbidden');
  });
});

describe('decorators', () => {
  it('@Policy() marks the class and makes it injectable', () => {
    @Policy()
    class MarkedPolicy {}

    @Injectable()
    class PlainService {}

    expect(Reflect.getMetadata(POLICY_METADATA, MarkedPolicy)).toBe(true);
    expect(Reflect.getMetadata(INJECTABLE_WATERMARK, MarkedPolicy)).toBe(true);
    expect(Reflect.getMetadata(POLICY_METADATA, PlainService)).toBeUndefined();
  });

  it('@Can() records stacked requirements top-down, separately on the class and on each method', () => {
    @Can(PostPolicy, 'viewAny')
    class Handlers {
      @Can(PostPolicy, 'viewStats')
      @Can(PostPolicy, 'exportStats')
      @Can(PostPolicy, 'create')
      stacked() {}

      plain() {}
    }

    expect(Reflect.getMetadata(CAN_METADATA, Handlers)).toEqual([{ policy: PostPolicy, ability: 'viewAny' }]);
    expect(Reflect.getMetadata(CAN_METADATA, Handlers.prototype.stacked)).toEqual([
      { policy: PostPolicy, ability: 'viewStats' },
      { policy: PostPolicy, ability: 'exportStats' },
      { policy: PostPolicy, ability: 'create' },
    ]);
    expect(Reflect.getMetadata(CAN_METADATA, Handlers.prototype.plain)).toBeUndefined();
  });
});
