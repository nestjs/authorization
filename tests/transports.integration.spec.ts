/**
 * Transport behaviors the README documents beyond the denial shapes in transports.e2e.spec.ts:
 * a hybrid app's message handlers with and without `inheritAppConfig`, the `getUser` recipe
 * that trusts a gateway-verified user in RPC payloads, and GraphQL field resolvers that call
 * `authorize()` with and without `fieldResolverEnhancers: ['interceptors']`.
 */
import type { AddressInfo, Server as NetServer } from 'node:net';
import { ApolloDriver, type ApolloDriverConfig } from '@nestjs/apollo';
import {
  Controller,
  Get,
  Injectable,
  Logger,
  Module,
  UseGuards,
  type CanActivate,
  type ExecutionContext,
  type INestApplication,
} from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { GraphQLModule, Parent, Query, ResolveField, Resolver } from '@nestjs/graphql';
import { ClientProxyFactory, MessagePattern, Transport, type ClientProxy } from '@nestjs/microservices';
import { Test } from '@nestjs/testing';
import { lastValueFrom } from 'rxjs';
import request from 'supertest';
import { createApp } from './support/adapters.js';
import {
  AuthorizationEvents,
  AuthorizationModule,
  AuthorizationService,
  Can,
  defaultGetUser,
  Policy,
  type AuthorizationDeniedEvent,
} from '../lib/index.js';
import { users, type User } from './fixtures.js';

@Policy()
class RefundPolicy {
  approve(user: User | null) {
    return !!user?.roles.includes('finance');
  }

  view(user: User | null, refund: { ownerId: number }) {
    return refund.ownerId === user?.id;
  }
}

const finance: User = { id: 10, roles: ['finance'] };

@Injectable()
class RefundsService {
  constructor(private readonly authorizationService: AuthorizationService) {}

  async show(user: User | null, ownerId: number) {
    await this.authorizationService.authorize(RefundPolicy, 'view', user, { ownerId });
    return { ownerId };
  }
}

/** Sets `request.user` from `x-user` over HTTP; leaves other transports alone. */
@Injectable()
class HeaderAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    if (context.getType() === 'http') {
      const req = context.switchToHttp().getRequest();
      req.user = req.headers['x-user'] === 'finance' ? finance : users[req.headers['x-user']];
    }
    return true;
  }
}

@Controller()
class RefundsController {
  constructor(private readonly refundsService: RefundsService) {}

  @Get('refunds/approve')
  @Can(RefundPolicy, 'approve')
  approveOverHttp() {
    return 'approved';
  }

  @MessagePattern('refunds.approve')
  @Can(RefundPolicy, 'approve')
  approve() {
    return 'approved';
  }

  @MessagePattern('refunds.show')
  show() {
    return this.refundsService.show(null, 1);
  }
}

async function hybrid(module: object, inheritAppConfig: boolean) {
  const app = (await Test.createTestingModule({ imports: [module as never] }).compile()).createNestApplication();
  const microservice = app.connectMicroservice({ transport: Transport.TCP, options: { host: '127.0.0.1', port: 0 } }, { inheritAppConfig });
  await app.startAllMicroservices();
  await app.listen(0, '127.0.0.1');

  const { port } = microservice.unwrap<NetServer>().address() as AddressInfo;
  const client = ClientProxyFactory.create({ transport: Transport.TCP, options: { host: '127.0.0.1', port } });
  await client.connect();
  return { app, client };
}

const send = (client: ClientProxy, pattern: string, data: object = {}) =>
  lastValueFrom(client.send(pattern, data)).then(
    (reply: unknown) => ({ reply }),
    (error: unknown) => ({ error }),
  );

describe('hybrid app: authorize() in message handlers', () => {
  @Module({
    imports: [AuthorizationModule.forRoot({ policies: [RefundPolicy] })],
    controllers: [RefundsController],
    providers: [RefundsService],
  })
  class HybridAppModule {}

  let running: { app: INestApplication; client: ClientProxy } | undefined;
  afterEach(async () => {
    await running?.client.close();
    await running?.app.close();
    running = undefined;
    vi.restoreAllMocks();
  });

  it('maps a service denial to an RpcException with inheritAppConfig: true', async () => {
    running = await hybrid(HybridAppModule, true);
    expect(await send(running.client, 'refunds.show')).toEqual({ error: { message: 'Unauthorized', statusCode: 401 } });
  });

  it('leaves it to the rpc filter without inheritAppConfig, which reports "Internal server error"', async () => {
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    running = await hybrid(HybridAppModule, false);
    expect(await send(running.client, 'refunds.show')).toEqual({ error: { status: 'error', message: 'Internal server error' } });
  });
});

describe('hybrid app: a getUser that trusts a gateway-verified user in RPC payloads', () => {
  @Module({
    imports: [
      AuthorizationModule.forRoot({
        policies: [RefundPolicy],
        getUser: (ctx) => (ctx.getType() === 'rpc' ? ctx.switchToRpc().getData<{ user?: User }>().user : defaultGetUser(ctx)),
      }),
    ],
    controllers: [RefundsController],
    providers: [RefundsService, { provide: APP_GUARD, useClass: HeaderAuthGuard }],
  })
  class GatewayAppModule {}

  let running: { app: INestApplication; client: ClientProxy };
  beforeAll(async () => {
    running = await hybrid(GatewayAppModule, true);
  });
  afterAll(async () => {
    await running.client.close();
    await running.app.close();
  });

  it('reads the user from the message payload over RPC', async () => {
    expect(await send(running.client, 'refunds.approve', { user: finance })).toEqual({ reply: 'approved' });
    expect(await send(running.client, 'refunds.approve', { user: users.alice })).toEqual({ error: { message: 'Forbidden', statusCode: 403 } });
    expect(await send(running.client, 'refunds.approve')).toEqual({ error: { message: 'Unauthorized', statusCode: 401 } });
  });

  it('delegates HTTP to defaultGetUser, which reads request.user and never a payload', async () => {
    const http = () => request(running.app.getHttpServer());
    await http().get('/refunds/approve').set('x-user', 'finance').expect(200, 'approved');
    await http().get('/refunds/approve').set('x-user', 'alice').expect(403);
    await http().get('/refunds/approve').query({ user: 'finance' }).expect(401);
  });
});

describe('GraphQL field resolvers that call authorize()', () => {
  type Employee = { id: number; name: string };

  @Policy()
  class SalaryPolicy {
    view(user: User | null, employee: Employee) {
      return employee.id === user?.id;
    }
  }

  @Injectable()
  class SalariesService {
    constructor(private readonly authorizationService: AuthorizationService) {}

    async salaryOf(user: User | null, employee: Employee) {
      await this.authorizationService.authorize(SalaryPolicy, 'view', user, employee);
      return 100_000;
    }
  }

  @Resolver('Employee')
  class EmployeesResolver {
    constructor(private readonly salariesService: SalariesService) {}

    @Query('employees')
    employees(): Employee[] {
      return [{ id: 1, name: 'Alice' }];
    }

    @ResolveField('salary')
    salary(@Parent() employee: Employee) {
      return this.salariesService.salaryOf(null, employee);
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
      providers: [EmployeesResolver, SalariesService],
    })
    class GqlAppModule {}
    return createApp('express', GqlAppModule);
  };

  const salaryError = async (app: INestApplication) => {
    const { body } = await request(app.getHttpServer()).post('/graphql').send({ query: '{ employees { name salary } }' }).expect(200);
    expect(body.data.employees).toEqual([{ name: 'Alice', salary: null }]);
    return body.errors[0];
  };

  let app: INestApplication | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
    vi.restoreAllMocks();
  });

  it("maps the denial with fieldResolverEnhancers: ['interceptors'], and still reports it", async () => {
    app = await appWith(['interceptors']);
    const events: AuthorizationDeniedEvent[] = [];
    app.get(AuthorizationEvents).events$.subscribe((event) => events.push(event));

    expect(await salaryError(app)).toMatchObject({ message: 'Unauthorized', path: ['employees', 0, 'salary'], extensions: { code: 'UNAUTHENTICATED' } });
    expect(events).toEqual([expect.objectContaining({ policy: 'SalaryPolicy', ability: 'view', args: [{ id: 1, name: 'Alice' }] })]);
  });

  it('leaves it unmapped without the interceptors enhancer: the field fails as an internal error', async () => {
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    app = await appWith([]);
    const error = await salaryError(app);
    expect(error.path).toEqual(['employees', 0, 'salary']);
    expect(error.extensions.code).toBe('INTERNAL_SERVER_ERROR');
  });
});

describe('guards of your own that run before the handler', () => {
  @Policy()
  class ReportPolicy {
    export(user: User | null) {
      return !!user?.roles.includes('exporter');
    }
  }

  /** Checks with can() and throws what the guard layer expects. */
  @Injectable()
  class ExportGuard implements CanActivate {
    constructor(private readonly authorizationService: AuthorizationService) {}

    async canActivate(context: ExecutionContext) {
      const user = context.switchToHttp().getRequest().user ?? null;
      return this.authorizationService.can(ReportPolicy, 'export', user);
    }
  }

  /** Lets an AuthorizationError escape: the interceptor that maps it has not run yet. */
  @Injectable()
  class AuthorizingGuard implements CanActivate {
    constructor(private readonly authorizationService: AuthorizationService) {}

    async canActivate(context: ExecutionContext) {
      await this.authorizationService.authorize(ReportPolicy, 'export', context.switchToHttp().getRequest().user ?? null);
      return true;
    }
  }

  @Controller('reports')
  class ReportsController {
    @Get('checked')
    @UseGuards(ExportGuard)
    checked() {
      return 'csv';
    }

    @Get('escaped')
    @UseGuards(AuthorizingGuard)
    escaped() {
      return 'csv';
    }
  }

  @Module({
    imports: [AuthorizationModule.forRoot({ policies: [ReportPolicy] })],
    controllers: [ReportsController],
    providers: [{ provide: APP_GUARD, useClass: HeaderAuthGuard }],
  })
  class ReportsAppModule {}

  let app: INestApplication;
  beforeAll(async () => {
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    app = await createApp('express', ReportsAppModule);
  });
  afterAll(async () => {
    await app.close();
    vi.restoreAllMocks();
  });

  it('a guard that checks with can() gets the 403 its layer gives a false', async () => {
    await request(app.getHttpServer()).get('/reports/checked').set('x-user', 'xavier').expect(200, 'csv');
    await request(app.getHttpServer()).get('/reports/checked').set('x-user', 'alice').expect(403);
  });

  it('an AuthorizationError escaping a guard is a 500', async () => {
    await request(app.getHttpServer()).get('/reports/escaped').set('x-user', 'xavier').expect(200, 'csv');
    await request(app.getHttpServer()).get('/reports/escaped').set('x-user', 'alice').expect(500);
  });
});
