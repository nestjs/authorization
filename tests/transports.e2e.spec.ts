/**
 * Denials in every transport: `@Can()` (the guard) and `authorize()` (an
 * `AuthorizationError` leaving the handler) must reach the client in the
 * transport's own error shape, the same for both.
 */
import type { IncomingMessage } from 'node:http';
import type { AddressInfo, Server as NetServer } from 'node:net';
import { ApolloDriver, type ApolloDriverConfig } from '@nestjs/apollo';
import {
  Controller,
  ForbiddenException,
  Injectable,
  Module,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
  type INestApplication,
  type INestMicroservice,
} from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { GraphQLModule, Query, ResolveField, Resolver } from '@nestjs/graphql';
import {
  ClientProxyFactory,
  MessagePattern,
  Payload,
  RpcException,
  Transport,
  type ClientProxy,
} from '@nestjs/microservices';
import { WsAdapter } from '@nestjs/platform-ws';
import { SubscribeMessage, WebSocketGateway, type OnGatewayConnection } from '@nestjs/websockets';
import { Test } from '@nestjs/testing';
import { lastValueFrom, throwError } from 'rxjs';
import request from 'supertest';
import { WebSocket } from 'ws';
import { createApp } from './support/adapters.js';
import { AuthorizationErrorInterceptor } from '../lib/interceptors/authorization-error.interceptor.js';
import {
  AuthorizationError,
  AuthorizationGuard,
  AuthorizationModule,
  AuthorizationService,
  Can,
  Policy,
} from '../lib/index.js';
import { PostPolicy, users, type Post } from './fixtures.js';

const draft: Post = { id: 2, authorId: 2, title: 'Bob drafts', published: false };

/** Record checks the way the tutorial does them: in a service, with `authorize()`. */
@Injectable()
class DraftsService {
  constructor(private readonly authz: AuthorizationService) {}

  async show(user: (typeof users)[string] | null) {
    await this.authz.authorize(PostPolicy, 'view', user, draft);
    return draft.title;
  }
}

describe('WebSocket gateway (platform-ws)', () => {
  @WebSocketGateway({ path: '/ws' })
  class PostsGateway implements OnGatewayConnection {
    constructor(private readonly drafts: DraftsService) {}

    handleConnection(client: WebSocket & { user?: unknown }, request: IncomingMessage) {
      client.user = users[new URL(request.url!, 'http://x').searchParams.get('user') ?? ''];
    }

    @SubscribeMessage('create')
    @Can(PostPolicy, 'create')
    create() {
      return { event: 'created', data: true };
    }

    @SubscribeMessage('draft')
    async show(client: { user?: (typeof users)[string] }) {
      return { event: 'draft', data: await this.drafts.show(client.user ?? null) };
    }
  }

  @Module({
    imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] })],
    providers: [DraftsService, PostsGateway],
  })
  class WsAppModule {}

  let app: INestApplication;
  let base: string;
  const sockets: WebSocket[] = [];
  /** The reply as sent over the wire. */
  const send = async (user: string | undefined, event: string) => {
    const socket = new WebSocket(`${base}/ws${user ? `?user=${user}` : ''}`);
    sockets.push(socket);
    await new Promise((resolve, reject) => socket.once('open', resolve).once('error', reject));
    const reply = new Promise<string>((resolve) => socket.once('message', (raw) => resolve(String(raw))));
    socket.send(JSON.stringify({ event, data: {} }));
    return reply;
  };
  const ask = async (user: string | undefined, event: string): Promise<unknown> => JSON.parse(await send(user, event));

  beforeAll(async () => {
    app = await createApp('express', WsAppModule, { setup: (a) => void a.useWebSocketAdapter(new WsAdapter(a)) });
    base = `ws://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}`;
  });
  afterEach(() => sockets.splice(0).forEach((socket) => socket.close()));
  afterAll(() => app.close());

  it('@Can() denials arrive as ws exceptions, not "Internal server error"', async () => {
    expect(await ask('alice', 'create')).toEqual({ event: 'created', data: true });

    expect(await ask('eve', 'create')).toEqual({
      event: 'exception',
      data: { status: 'error', message: 'Forbidden', statusCode: 403 },
    });

    expect(await ask(undefined, 'create')).toEqual({
      event: 'exception',
      data: { status: 'error', message: 'Unauthorized', statusCode: 401 },
    });
  });

  it('authorize() denials in a service arrive the same way', async () => {
    expect(await ask('bob', 'draft')).toEqual({ event: 'draft', data: 'Bob drafts' });
    expect(await ask('alice', 'draft')).toEqual({
      event: 'exception',
      data: { status: 'error', message: 'Forbidden', statusCode: 403 },
    });
  });

  it("carries the body of Nest's own ForbiddenException, after the ws filter's status", async () => {
    expect(await send('eve', 'create')).toBe(
      '{"event":"exception","data":{"status":"error","message":"Forbidden","statusCode":403}}',
    );
    const { data } = (await ask('eve', 'create')) as { data: Record<string, unknown> };
    const { status: _, ...body } = data;
    expect(JSON.stringify(body)).toBe(JSON.stringify(new ForbiddenException().getResponse()));
  });
});

describe('GraphQL (Apollo, express)', () => {
  /** Sets `req.user` from `x-user`, on HTTP and GraphQL requests. */
  @Injectable()
  class HeaderAuthGuard implements CanActivate {
    canActivate(context: ExecutionContext) {
      const req = context.getType<string>() === 'graphql' ? context.getArgByIndex(2).req : context.switchToHttp().getRequest();
      req.user = users[req.headers['x-user']];
      return true;
    }
  }

  @Resolver()
  class PostsResolver {
    constructor(private readonly drafts: DraftsService) {}

    @Query('create')
    @Can(PostPolicy, 'create')
    create() {
      return true;
    }

    @Query('draft')
    draft() {
      return this.drafts.show(null);
    }
  }

  @Module({
    imports: [
      GraphQLModule.forRoot<ApolloDriverConfig>({
        driver: ApolloDriver,
        typeDefs: 'type Query { create: Boolean, draft: String }',
        context: ({ req }: { req: unknown }) => ({ req }),
      }),
      AuthorizationModule.forRoot({ policies: [PostPolicy] }),
    ],
    providers: [{ provide: APP_GUARD, useClass: HeaderAuthGuard }, DraftsService, PostsResolver],
  })
  class GqlAppModule {}

  let app: INestApplication;
  const gql = (query: string, user?: string) => {
    const req = request(app.getHttpServer()).post('/graphql');
    if (user) {
      req.set('x-user', user);
    }
    return req.send({ query });
  };

  beforeAll(async () => {
    app = await createApp('express', GqlAppModule);
  });
  afterAll(() => app.close());

  it('@Can() denials carry FORBIDDEN / UNAUTHENTICATED', async () => {
    expect((await gql('{ create }', 'alice').expect(200)).body.data).toEqual({ create: true });

    expect((await gql('{ create }', 'eve').expect(200)).body.errors[0]).toMatchObject({
      message: 'Forbidden',
      extensions: { code: 'FORBIDDEN' },
    });

    expect((await gql('{ create }').expect(200)).body.errors[0]).toMatchObject({
      message: 'Unauthorized',
      extensions: { code: 'UNAUTHENTICATED' },
    });
  });

  it('authorize() denials in a service carry the same code', async () => {
    expect((await gql('{ draft }').expect(200)).body.errors[0]).toMatchObject({
      message: 'Unauthorized',
      extensions: { code: 'UNAUTHENTICATED' },
    });
  });
});

describe('GraphQL field resolvers', () => {
  @Policy()
  class SalaryPolicy {
    viewSalary(user: (typeof users)[string] | null) {
      return !!user?.roles.includes('admin');
    }
  }

  @Resolver('Employee')
  class EmployeesResolver {
    @Query('employees')
    employees() {
      return [{ name: 'Sam' }];
    }

    @ResolveField('salary')
    @Can(SalaryPolicy, 'viewSalary')
    salary() {
      return 100000;
    }
  }

  const appWith = (fieldResolverEnhancers: ('guards' | 'interceptors' | 'filters')[]) => {
    @Module({
      imports: [
        GraphQLModule.forRoot<ApolloDriverConfig>({
          driver: ApolloDriver,
          typeDefs: 'type Employee { name: String, salary: Int } type Query { employees: [Employee] }',
          fieldResolverEnhancers,
          context: ({ req }: { req: unknown }) => ({ req }),
        }),
        AuthorizationModule.forRoot({ policies: [SalaryPolicy] }),
      ],
      providers: [EmployeesResolver],
    })
    class GqlAppModule {}
    return createApp('express', GqlAppModule);
  };

  // GraphQL runs no guard on field resolvers by default, so the @Can() would let every caller through.
  it('fails the startup for @Can() on a field resolver that GraphQL runs without guards', async () => {
    await expect(appWith([])).rejects.toThrow(
      "@Can(SalaryPolicy, 'viewSalary') on EmployeesResolver.salary is not enforced: GraphQL runs guards on " +
        "field resolvers only with fieldResolverEnhancers: ['guards'] in the GraphQLModule options.",
    );
  });

  it("enforces it with fieldResolverEnhancers: ['guards']", async () => {
    const app = await appWith(['guards']);
    try {
      const { body } = await request(app.getHttpServer()).post('/graphql').send({ query: '{ employees { name salary } }' });
      expect(body.errors[0]).toMatchObject({ path: ['employees', 0, 'salary'], extensions: { code: 'UNAUTHENTICATED' } });
    } finally {
      await app.close();
    }
  });

  it("leaves a class-level @Can() to the resolver's queries, as Nest does with class-level guards", async () => {
    @Resolver('Employee')
    @Can(SalaryPolicy, 'viewSalary')
    class PayrollResolver {
      @Query('employees')
      employees() {
        return [{ name: 'Sam' }];
      }

      @ResolveField('salary')
      salary() {
        return 100000;
      }
    }

    @Module({
      imports: [
        GraphQLModule.forRoot<ApolloDriverConfig>({
          driver: ApolloDriver,
          typeDefs: 'type Employee { name: String, salary: Int } type Query { employees: [Employee] }',
          context: ({ req }: { req: unknown }) => ({ req }),
        }),
        AuthorizationModule.forRoot({ policies: [SalaryPolicy] }),
      ],
      providers: [PayrollResolver],
    })
    class PayrollAppModule {}

    const app = await createApp('express', PayrollAppModule);

    try {
      const { body } = await request(app.getHttpServer()).post('/graphql').send({ query: '{ employees { name salary } }' });
      expect(body.errors[0]).toMatchObject({ path: ['employees'], extensions: { code: 'UNAUTHENTICATED' } });
    } finally {
      await app.close();
    }
  });
});

describe('microservice handlers (rpc)', () => {
  const rpcContext = (user: unknown) =>
    ({
      getType: () => 'rpc',
      getClass: () => class {},
      getHandler: () => handler,
      switchToRpc: () => ({ getContext: () => ({ user }), getData: () => ({}) }),
    }) as unknown as ExecutionContext;
  const handler = () => undefined;
  Can(PostPolicy, 'create')(handler, 'handler', { value: handler });

  let guard: AuthorizationGuard;
  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] })],
    }).compile();
    guard = moduleRef.get(AuthorizationGuard);
  });

  it('@Can() denials become RpcExceptions', async () => {
    expect(await guard.canActivate(rpcContext(users.alice))).toBe(true);
    const error = await guard.canActivate(rpcContext(users.eve)).catch((e) => e);
    expect(error).toBeInstanceOf(RpcException);
    expect(error.getError()).toEqual({ message: 'Forbidden', statusCode: 403 });
    expect(error.cause).toMatchObject({ reason: 'forbidden', policy: 'PostPolicy', ability: 'create' });
  });

  it("carries the bodies of Nest's own UnauthorizedException and ForbiddenException, as over HTTP", async () => {
    const forbidden = (await guard.canActivate(rpcContext(users.eve)).catch((e) => e)) as RpcException;
    expect(JSON.stringify(forbidden.getError())).toBe('{"message":"Forbidden","statusCode":403}');
    expect(forbidden.getError()).toEqual(new ForbiddenException().getResponse());

    const guest = (await guard.canActivate(rpcContext(null)).catch((e) => e)) as RpcException;
    expect(JSON.stringify(guest.getError())).toBe('{"message":"Unauthorized","statusCode":401}');
    expect(guest.getError()).toEqual(new UnauthorizedException().getResponse());
  });

  it('an AuthorizationError leaving the handler becomes the same RpcException', async () => {
    const denial = new AuthorizationError('unauthenticated', 'PostPolicy', 'view');
    const result = new AuthorizationErrorInterceptor().intercept(rpcContext(null), {
      handle: () => throwError(() => denial),
    });
    const error = await lastValueFrom(result).catch((e: RpcException) => e);
    expect(error).toBeInstanceOf(RpcException);
    expect((error as RpcException).getError()).toEqual({ message: 'Unauthorized', statusCode: 401 });
  });

  it('leaves other errors alone', async () => {
    const failure = new Error('database is down');
    const result = new AuthorizationErrorInterceptor().intercept(rpcContext(null), {
      handle: () => throwError(() => failure),
    });
    await expect(lastValueFrom(result)).rejects.toBe(failure);
  });
});

describe('microservice over TCP (a real transport)', () => {
  const finance = { id: 10, roles: ['finance'] };

  /**
   * Stands in for an authentication guard on RPC: like `@nestjs/authentication`,
   * it records the caller on the transport context, `null` when anonymous.
   */
  @Injectable()
  class TokenAuthGuard implements CanActivate {
    canActivate(context: ExecutionContext) {
      const rpc = context.switchToRpc();
      rpc.getContext().user = rpc.getData()?.token === 'finance-token' ? finance : null;
      return true;
    }
  }

  @Policy()
  class RefundPolicy {
    approve(user: (typeof users)[string] | null) {
      return !!user?.roles.includes('finance');
    }
  }

  @Controller()
  class RefundsController {
    constructor(private readonly drafts: DraftsService) {}

    @MessagePattern('refunds.approve')
    @Can(RefundPolicy, 'approve')
    approve(@Payload() data: { orderId: number }) {
      return { approved: data.orderId };
    }

    @MessagePattern('drafts.show')
    show() {
      return this.drafts.show(null);
    }
  }

  @Module({
    imports: [AuthorizationModule.forRoot({ policies: [PostPolicy, RefundPolicy] })],
    controllers: [RefundsController],
    providers: [{ provide: APP_GUARD, useClass: TokenAuthGuard }, DraftsService],
  })
  class RpcAppModule {}

  let app: INestMicroservice;
  let client: ClientProxy;
  const send = (pattern: string, data: object) =>
    lastValueFrom(client.send(pattern, data)).then(
      (reply: unknown) => ({ reply }),
      (error: unknown) => ({ error }),
    );

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [RpcAppModule] }).compile();
    app = moduleRef.createNestMicroservice({ transport: Transport.TCP, options: { host: '127.0.0.1', port: 0 } });
    await app.listen();

    const { port } = app.unwrap<NetServer>().address() as AddressInfo;
    client = ClientProxyFactory.create({ transport: Transport.TCP, options: { host: '127.0.0.1', port } });
    await client.connect();
  });
  afterAll(async () => {
    await client.close();
    await app.close();
  });

  it('@Can() reads the user the authentication guard left on the transport context', async () => {
    expect(await send('refunds.approve', { orderId: 3, token: 'finance-token' })).toEqual({ reply: { approved: 3 } });
    expect(await send('refunds.approve', { orderId: 3 })).toEqual({
      error: { message: 'Unauthorized', statusCode: 401 },
    });
  });

  it('never takes the user from the message payload, which the producer writes', async () => {
    const admin = { id: 1, roles: ['admin', 'finance'] };
    expect(await send('refunds.approve', { orderId: 3, user: admin })).toEqual({
      error: { message: 'Unauthorized', statusCode: 401 },
    });
  });

  it('authorize() denials in a service reach the client in the same shape', async () => {
    expect(await send('drafts.show', {})).toEqual({ error: { message: 'Unauthorized', statusCode: 401 } });
  });
});

describe('hybrid app (HTTP plus a connected microservice)', () => {
  @Policy()
  class RefundPolicy {
    approve(user: (typeof users)[string] | null) {
      return !!user?.roles.includes('finance');
    }
  }

  @Controller()
  class RefundsController {
    @MessagePattern('refunds.approve')
    @Can(RefundPolicy, 'approve')
    approve() {
      return 'approved';
    }
  }

  @Module({ imports: [AuthorizationModule.forRoot({ policies: [RefundPolicy] })], controllers: [RefundsController] })
  class HybridAppModule {}

  /** What a guest gets from the @Can() message handler. */
  async function guestCall(inheritAppConfig: boolean) {
    const app = (await Test.createTestingModule({ imports: [HybridAppModule] }).compile()).createNestApplication();
    const microservice = app.connectMicroservice(
      { transport: Transport.TCP, options: { host: '127.0.0.1', port: 0 } },
      { inheritAppConfig },
    );
    await app.startAllMicroservices();
    await app.listen(0, '127.0.0.1');

    const { port } = microservice.unwrap<NetServer>().address() as AddressInfo;
    const client = ClientProxyFactory.create({ transport: Transport.TCP, options: { host: '127.0.0.1', port } });

    try {
      return await lastValueFrom(client.send('refunds.approve', {})).then(
        (reply: unknown) => ({ reply }),
        (error: unknown) => ({ error }),
      );
    } finally {
      await client.close();
      await app.close();
    }
  }

  // Nest gives a connected microservice the app's global enhancers (APP_GUARD
  // included) only with inheritAppConfig: true. The README says so.
  it('enforces @Can() on message handlers with inheritAppConfig: true, and only then', async () => {
    expect(await guestCall(true)).toEqual({ error: { message: 'Unauthorized', statusCode: 401 } });
    expect(await guestCall(false)).toEqual({ reply: 'approved' });
  });
});
