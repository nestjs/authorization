import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  NotFoundException,
  UnauthorizedException,
  type ExecutionContext,
} from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { WsException } from '@nestjs/websockets';
import { Test, type TestingModule } from '@nestjs/testing';
import { lastValueFrom, of, throwError } from 'rxjs';
import { AuthorizationErrorInterceptor } from '../lib/interceptors/authorization-error.interceptor.js';
import { toTransportError } from '../lib/utils/transport-error.util.js';
import {
  AUTHORIZATION_MODULE_OPTIONS,
  AuthorizationError,
  AuthorizationEvents,
  AuthorizationGuard,
  AuthorizationModule,
  Can,
  defaultGetUser,
  Policy,
  type AuthorizationDeniedEvent,
} from '../lib/index.js';
import { users, type User } from './fixtures.js';

const evaluated: string[] = [];

@Policy()
class SteppingPolicy {
  first(user: User | null) {
    evaluated.push('first');
    return user !== null;
  }

  second(user: User | null) {
    evaluated.push('second');
    return !!user?.roles.includes('editor');
  }

  third(_user: User | null) {
    evaluated.push('third');
    return true;
  }
}

@Can(SteppingPolicy, 'first')
class SteppingController {
  @Can(SteppingPolicy, 'second')
  @Can(SteppingPolicy, 'third')
  guarded() {}

  open() {}
}

@Can(SteppingPolicy, 'third')
class ClassOnlyController {
  handler() {}
}

@Policy()
class WorkoutPolicy {
  before(_user: User | null, ability: string, ...args: unknown[]) {
    evaluated.push(`before:${ability}:${args.join(',')}`);
    return undefined;
  }

  view(user: User | null, workoutId: string) {
    evaluated.push(`view:${workoutId}`);
    return user?.id === 1 && workoutId === 'w1';
  }
}

const workoutIdOf = (context: ExecutionContext) => [context.switchToHttp().getRequest().params.workoutId as string] as const;

@Can(SteppingPolicy, 'first')
class WorkoutsController {
  @Can(WorkoutPolicy, 'view', workoutIdOf)
  findOne() {}
}

/** An `http` context for `handler` of `type`, whose request carries `user`. */
const httpContext = (type: Function, handler: Function, user?: unknown) =>
  ({
    getType: () => 'http',
    getClass: () => type,
    getHandler: () => handler,
    switchToHttp: () => ({ getRequest: () => ({ user }) }),
  }) as unknown as ExecutionContext;

/** An `http` context whose request carries `user` and route `params`. */
const requestContext = (type: Function, handler: Function, user: unknown, params: Record<string, string>) =>
  ({
    getType: () => 'http',
    getClass: () => type,
    getHandler: () => handler,
    switchToHttp: () => ({ getRequest: () => ({ user, params }) }),
  }) as unknown as ExecutionContext;

const contextOf = (type: string) => ({ getType: () => type }) as unknown as ExecutionContext;

describe('AuthorizationGuard', () => {
  let moduleRef: TestingModule;
  let guard: AuthorizationGuard;
  const denials: AuthorizationDeniedEvent[] = [];

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      imports: [AuthorizationModule.forRoot({ policies: [SteppingPolicy, WorkoutPolicy] })],
    }).compile();
    await moduleRef.init();
    guard = moduleRef.get(AuthorizationGuard);
    moduleRef.get(AuthorizationEvents).events$.subscribe((event) => denials.push(event));
  });
  afterAll(() => moduleRef.close());
  beforeEach(() => {
    evaluated.length = 0;
    denials.length = 0;
  });

  it('runs class-level requirements first, then the method-level ones top-down', async () => {
    const erin = { id: 5, roles: ['editor'] };

    expect(await guard.canActivate(httpContext(SteppingController, SteppingController.prototype.guarded, erin))).toBe(true);
    expect(evaluated).toEqual(['first', 'second', 'third']);
  });

  it('stops at the first requirement that denies, and reports only that one with the handler', async () => {
    const error = await guard
      .canActivate(httpContext(SteppingController, SteppingController.prototype.guarded, users.alice))
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ForbiddenException);
    expect(evaluated).toEqual(['first', 'second']);
    expect(denials).toEqual([
      {
        type: 'denied',
        policy: 'SteppingPolicy',
        ability: 'second',
        reason: 'forbidden',
        user: users.alice,
        args: [],
        handler: 'SteppingController.guarded',
      },
    ]);
  });

  it('denies a guest at the class-level requirement with 401 before any method-level one runs', async () => {
    const error = await guard
      .canActivate(httpContext(SteppingController, SteppingController.prototype.guarded))
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(UnauthorizedException);
    expect(evaluated).toEqual(['first']);
    expect(denials[0]).toMatchObject({ ability: 'first', reason: 'unauthenticated', user: null });
  });

  it('applies a class-level requirement to a method without its own', async () => {
    expect(await guard.canActivate(httpContext(ClassOnlyController, ClassOnlyController.prototype.handler))).toBe(true);
    expect(evaluated).toEqual(['third']);
  });

  it('carries the AuthorizationError as the cause, with the policy and ability the body leaves out', async () => {
    const error = (await guard
      .canActivate(httpContext(SteppingController, SteppingController.prototype.guarded, users.alice))
      .catch((e: unknown) => e)) as HttpException;

    expect(error.getResponse()).toEqual({ message: 'Forbidden', statusCode: 403 });
    expect(error.cause).toBeInstanceOf(AuthorizationError);
    expect(error.cause).toMatchObject({ policy: 'SteppingPolicy', ability: 'second', reason: 'forbidden' });
  });

  describe('arguments read from the call', () => {
    const findOne = (user: User | undefined, workoutId: string) =>
      requestContext(WorkoutsController, WorkoutsController.prototype.findOne, user, { workoutId });

    it('hands before() and the ability the arguments its resolver reads', async () => {
      expect(await guard.canActivate(findOne(users.alice, 'w1'))).toBe(true);
      expect(evaluated).toEqual(['first', 'before:view:w1', 'view:w1']);
    });

    it('reports the arguments with the denial', async () => {
      await expect(guard.canActivate(findOne(users.alice, 'w2'))).rejects.toBeInstanceOf(ForbiddenException);
      expect(denials).toEqual([
        {
          type: 'denied',
          policy: 'WorkoutPolicy',
          ability: 'view',
          reason: 'forbidden',
          user: users.alice,
          args: ['w2'],
          handler: 'WorkoutsController.findOne',
        },
      ]);
    });

    it('runs no resolver once an earlier requirement denies', async () => {
      const resolve = vi.fn(workoutIdOf);
      @Can(SteppingPolicy, 'first')
      class Guarded {
        @Can(WorkoutPolicy, 'view', resolve)
        findOne() {}
      }

      await expect(
        guard.canActivate(requestContext(Guarded, Guarded.prototype.findOne, undefined, { workoutId: 'w1' })),
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(resolve).not.toHaveBeenCalled();
    });

    it('awaits an async resolver, and lets an error it throws through as it is, reporting no denial', async () => {
      class Async {
        @Can(WorkoutPolicy, 'view', async () => ['w1'])
        allowed() {}

        @Can(WorkoutPolicy, 'view', () => {
          throw new BadRequestException('workoutId is required');
        })
        broken() {}
      }

      expect(await guard.canActivate(requestContext(Async, Async.prototype.allowed, users.alice, {}))).toBe(true);
      await expect(guard.canActivate(requestContext(Async, Async.prototype.broken, users.alice, {}))).rejects.toThrow(
        new BadRequestException('workoutId is required'),
      );
      expect(denials).toEqual([]);
    });

    it('fails when a resolver returns something other than an array', async () => {
      class Untyped {
        @Can(WorkoutPolicy, 'view', (() => 'w1') as never)
        findOne() {}
      }

      await expect(
        guard.canActivate(requestContext(Untyped, Untyped.prototype.findOne, users.alice, {})),
      ).rejects.toThrow(
        "The args of @Can(WorkoutPolicy, 'view') must return an array: the ability's arguments after the user.",
      );
    });
  });

  it('lets a handler without @Can() through without asking for the user', async () => {
    const getUser = vi.fn();
    const custom = await Test.createTestingModule({
      imports: [AuthorizationModule.forRoot({ policies: [SteppingPolicy], getUser })],
    }).compile();
    await custom.init();

    const plain = class PlainController {
      handler() {}
    };
    expect(await custom.get(AuthorizationGuard).canActivate(httpContext(plain, plain.prototype.handler))).toBe(true);
    expect(getUser).not.toHaveBeenCalled();
    await custom.close();
  });

  it('asks a custom getUser once per request, with the execution context, however many requirements apply', async () => {
    const erin = { id: 5, roles: ['editor'] };
    const getUser = vi.fn(async () => erin);
    const custom = await Test.createTestingModule({
      imports: [AuthorizationModule.forRoot({ policies: [SteppingPolicy], getUser })],
    }).compile();
    await custom.init();

    const context = httpContext(SteppingController, SteppingController.prototype.guarded, users.alice);
    expect(await custom.get(AuthorizationGuard).canActivate(context)).toBe(true);
    expect(getUser).toHaveBeenCalledTimes(1);
    expect(getUser).toHaveBeenCalledWith(context);
    await custom.close();
  });

  it('falls back to defaultGetUser when a forRootAsync() factory resolves to nothing', async () => {
    const custom = await Test.createTestingModule({
      imports: [AuthorizationModule.forRootAsync({ useFactory: () => undefined as never, policies: [SteppingPolicy] })],
    }).compile();
    await custom.init();

    expect(custom.get(AUTHORIZATION_MODULE_OPTIONS)).toBeUndefined();
    const guardOf = custom.get(AuthorizationGuard);
    const erin = { id: 5, roles: ['editor'] };
    expect(await guardOf.canActivate(httpContext(SteppingController, SteppingController.prototype.guarded, erin))).toBe(true);
    await expect(
      guardOf.canActivate(httpContext(SteppingController, SteppingController.prototype.guarded)),
    ).rejects.toBeInstanceOf(UnauthorizedException);
    await custom.close();
  });

  it('treats a getUser returning false or undefined as a guest', async () => {
    for (const user of [false, undefined]) {
      const custom = await Test.createTestingModule({
        imports: [AuthorizationModule.forRoot({ policies: [SteppingPolicy], getUser: () => user })],
      }).compile();
      await custom.init();

      await expect(
        custom.get(AuthorizationGuard).canActivate(httpContext(SteppingController, SteppingController.prototype.guarded)),
      ).rejects.toBeInstanceOf(UnauthorizedException);
      await custom.close();
    }
  });
});

describe('toTransportError', () => {
  const forbidden = new AuthorizationError('forbidden', 'PostPolicy', 'create');
  const guest = new AuthorizationError('unauthenticated', 'PostPolicy', 'create');

  it('gives http and graphql the HTTP exceptions, with the denial as the cause', async () => {
    for (const type of ['http', 'graphql']) {
      const denied = await toTransportError(contextOf(type), forbidden);
      const unauthenticated = await toTransportError(contextOf(type), guest);

      expect(denied).toBeInstanceOf(ForbiddenException);
      expect(denied.cause).toBe(forbidden);
      expect(unauthenticated).toBeInstanceOf(UnauthorizedException);
      expect((unauthenticated as HttpException).getStatus()).toBe(401);
      expect(unauthenticated.cause).toBe(guest);
    }
  });

  it("gives ws a WsException with the ws filter's status in front of Nest's body", async () => {
    const error = await toTransportError(contextOf('ws'), guest);

    expect(error).toBeInstanceOf(WsException);
    expect((error as WsException).getError()).toEqual({ status: 'error', message: 'Unauthorized', statusCode: 401 });
    expect(error.cause).toBe(guest);
  });

  it('gives rpc an RpcException carrying the denial as the cause', async () => {
    const error = await toTransportError(contextOf('rpc'), forbidden);

    expect(error).toBeInstanceOf(RpcException);
    expect(error.cause).toBe(forbidden);
  });

  it('falls back to the HTTP exception for a context type it does not know', async () => {
    const error = await toTransportError(contextOf('kafka-custom'), forbidden);

    expect(error).toBeInstanceOf(ForbiddenException);
    expect((error as HttpException).getResponse()).toEqual({ message: 'Forbidden', statusCode: 403 });
  });
});

describe('AuthorizationErrorInterceptor', () => {
  const interceptor = new AuthorizationErrorInterceptor();

  it('passes values through untouched', async () => {
    const value = { id: 1 };

    expect(await lastValueFrom(interceptor.intercept(contextOf('http'), { handle: () => of(value) }))).toBe(value);
  });

  it('turns an AuthorizationError into the http exception, and leaves HTTP exceptions alone', async () => {
    const denial = new AuthorizationError('forbidden', 'PostPolicy', 'update');
    const mapped = await lastValueFrom(
      interceptor.intercept(contextOf('http'), { handle: () => throwError(() => denial) }),
    ).catch((e: unknown) => e);

    expect(mapped).toBeInstanceOf(ForbiddenException);
    expect((mapped as Error).cause).toBe(denial);

    const notFound = new NotFoundException();
    await expect(
      lastValueFrom(interceptor.intercept(contextOf('http'), { handle: () => throwError(() => notFound) })),
    ).rejects.toBe(notFound);
  });

  it('does not map an error that merely looks like a denial', async () => {
    const lookalike = Object.assign(new Error('Forbidden'), { name: 'AuthorizationError', status: 403, reason: 'forbidden' });

    await expect(
      lastValueFrom(interceptor.intercept(contextOf('http'), { handle: () => throwError(() => lookalike) })),
    ).rejects.toBe(lookalike);
  });

  it('maps a ws denial to a WsException', async () => {
    const denial = new AuthorizationError('forbidden', 'PostPolicy', 'update');
    const mapped = await lastValueFrom(
      interceptor.intercept(contextOf('ws'), { handle: () => throwError(() => denial) }),
    ).catch((e: unknown) => e);

    expect(mapped).toBeInstanceOf(WsException);
    expect((mapped as WsException).getError()).toEqual({ status: 'error', message: 'Forbidden', statusCode: 403 });
  });
});

describe('defaultGetUser edge cases', () => {
  const ctx = (type: string, parts: Record<string, any>) =>
    ({
      getType: () => type,
      switchToHttp: () => ({ getRequest: () => parts.request }),
      switchToWs: () => ({ getClient: () => parts.client }),
      switchToRpc: () => ({ getContext: () => parts.rpcContext }),
      getArgByIndex: (i: number) => parts.args?.[i],
    }) as unknown as ExecutionContext;

  it('answers undefined, without throwing, when the transport carries nothing', () => {
    expect(defaultGetUser(ctx('http', { request: undefined }))).toBeUndefined();
    expect(defaultGetUser(ctx('ws', { client: undefined }))).toBeUndefined();
    expect(defaultGetUser(ctx('ws', { client: {} }))).toBeUndefined();
    expect(defaultGetUser(ctx('rpc', { rpcContext: undefined }))).toBeUndefined();
    expect(defaultGetUser(ctx('graphql', { args: [{}, {}] }))).toBeUndefined();
    expect(defaultGetUser(ctx('graphql', { args: [{}, {}, {}] }))).toBeUndefined();
  });

  it('answers undefined for a context type it does not know', () => {
    expect(defaultGetUser(ctx('kafka-custom', { request: { user: 'h' } }))).toBeUndefined();
  });

  it("reads socket.io's data.user when client.user was never set, and keeps false (Passport) as set", () => {
    expect(defaultGetUser(ctx('ws', { client: { user: undefined, data: { user: 'sio' } } }))).toBe('sio');
    expect(defaultGetUser(ctx('ws', { client: { user: false, data: { user: 'sio' } } }))).toBe(false);
  });
});
