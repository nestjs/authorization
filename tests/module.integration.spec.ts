/**
 * Module setups from the README, booted on Express and Fastify and driven over HTTP: a
 * `getUser` from `forRootAsync()` that reads a request context (the CLS recipe), policies in
 * lazily loaded modules, `isGlobal: false`, a `before()` shared through a base class, and
 * what importing the module twice does.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import {
  Controller,
  Get,
  Injectable,
  Module,
  Req,
  type MiddlewareConsumer,
  type NestMiddleware,
  type NestModule,
  type INestApplication,
} from '@nestjs/common';
import { LazyModuleLoader } from '@nestjs/core';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  AuthorizationModule,
  AuthorizationService,
  Can,
  Policy,
  type Ability,
  type AuthorizationModuleOptions,
  type PolicyBefore,
} from '../lib/index.js';
import { PostPolicy, users, type User } from './fixtures.js';

@Controller('posts')
class PostsController {
  @Get()
  @Can(PostPolicy, 'create')
  create() {
    return 'created';
  }
}

describe.each(adapters.map((a) => a.name))('module setups over HTTP (%s)', (adapter) => {
  let app: INestApplication | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
  });
  const http = () => request(app!.getHttpServer());

  it('forRootAsync(): a getUser from an injected request context (the CLS recipe)', async () => {
    @Injectable()
    class ClsService {
      private readonly storage = new AsyncLocalStorage<{ user?: User }>();

      run(store: { user?: User }, fn: () => void) {
        this.storage.run(store, fn);
      }

      get(key: 'user') {
        return this.storage.getStore()?.[key];
      }
    }

    @Injectable()
    class ClsMiddleware implements NestMiddleware {
      constructor(private readonly cls: ClsService) {}

      use(req: { headers: Record<string, string> }, _res: unknown, next: () => void) {
        this.cls.run({ user: users[req.headers['x-user']] }, next);
      }
    }

    @Module({ providers: [ClsService, ClsMiddleware], exports: [ClsService, ClsMiddleware] })
    class ClsModule implements NestModule {
      configure(consumer: MiddlewareConsumer) {
        consumer.apply(ClsMiddleware).forRoutes('*path');
      }
    }

    @Module({
      imports: [
        ClsModule,
        AuthorizationModule.forRootAsync({
          imports: [ClsModule],
          inject: [ClsService],
          useFactory: (cls: ClsService): AuthorizationModuleOptions => ({ getUser: () => cls.get('user') }),
          policies: [PostPolicy],
        }),
      ],
      controllers: [PostsController],
    })
    class AppModule {}

    app = await createApp(adapter, AppModule);
    await http().get('/posts').expect(401);
    await http().get('/posts').set('x-user', 'eve').expect(403);
    await http().get('/posts').set('x-user', 'alice').expect(200, 'created');
  });

  it('finds a policy in a module the handler loads lazily, on first use', async () => {
    @Policy()
    class ExportPolicy {
      export(user: User | null) {
        return !!user?.roles.includes('exporter');
      }
    }

    @Module({ providers: [ExportPolicy] })
    class ExportsModule {}

    @Controller('exports')
    class ExportsController {
      constructor(
        private readonly lazyModuleLoader: LazyModuleLoader,
        private readonly authorizationService: AuthorizationService,
      ) {}

      @Get()
      @Can.Anyone()
      async export(@Req() req: { headers: Record<string, string> }) {
        await this.lazyModuleLoader.load(() => ExportsModule);
        await this.authorizationService.authorize(ExportPolicy, 'export', users[req.headers['x-user']]);
        return 'csv';
      }
    }

    @Module({ imports: [AuthorizationModule.forRoot()], controllers: [ExportsController] })
    class AppModule {}

    app = await createApp(adapter, AppModule);
    await http().get('/exports').set('x-user', 'alice').expect(403);
    await http().get('/exports').set('x-user', 'xavier').expect(200, 'csv');
    await http().get('/exports').expect(401);
  });

  it('isGlobal: false serves the module that imports it, the global guard included', async () => {
    @Controller('drafts')
    class DraftsController {
      constructor(private readonly authorizationService: AuthorizationService) {}

      @Get()
      @Can(PostPolicy, 'create')
      async list(@Req() req: { headers: Record<string, string> }) {
        return { canViewStats: await this.authorizationService.can(PostPolicy, 'viewStats', users[req.headers['x-user']]) };
      }
    }

    @Module({
      imports: [AuthorizationModule.forRoot({ isGlobal: false, policies: [PostPolicy], getUser: (ctx) => users[ctx.switchToHttp().getRequest().headers['x-user']] })],
      controllers: [DraftsController],
    })
    class DraftsModule {}

    @Module({ imports: [DraftsModule] })
    class AppModule {}

    app = await createApp(adapter, AppModule);
    await http().get('/drafts').set('x-user', 'eve').expect(403);
    await http().get('/drafts').set('x-user', 'alice').expect(200, { canViewStats: false });
  });

  it("shares a before() through a base class, excluding by name the abilities that bind everyone (Gate::before)", async () => {
    type Order = { id: number; status: 'paid' | 'shipped' };

    abstract class AppPolicy<P> implements PolicyBefore<User, Ability<P>> {
      protected readonly bindsEveryone: string[] = [];

      before(user: User | null, ability: Ability<P>) {
        if (!this.bindsEveryone.includes(ability) && user?.roles.includes('admin')) {
          return true;
        }
        return undefined;
      }
    }

    @Policy()
    class OrderPolicy extends AppPolicy<OrderPolicy> {
      protected readonly bindsEveryone = ['refund'];

      view(_user: User | null) {
        return false;
      }

      refund(_user: User | null, order: Order) {
        return order.status === 'paid';
      }
    }

    @Controller('orders')
    class OrdersController {
      constructor(private readonly authorizationService: AuthorizationService) {}

      @Get()
      @Can(OrderPolicy, 'view')
      list() {
        return [];
      }

      @Get('refund')
      @Can.Anyone()
      async refund(@Req() req: { headers: Record<string, string>; query: { status: Order['status'] } }) {
        await this.authorizationService.authorize(OrderPolicy, 'refund', users[req.headers['x-user']], { id: 1, status: req.query.status });
        return 'refunded';
      }
    }

    @Module({
      imports: [AuthorizationModule.forRoot({ getUser: (ctx) => users[ctx.switchToHttp().getRequest().headers['x-user']] })],
      controllers: [OrdersController],
      providers: [OrderPolicy],
    })
    class AppModule {}

    app = await createApp(adapter, AppModule);
    await http().get('/orders').set('x-user', 'alice').expect(403);
    await http().get('/orders').set('x-user', 'root').expect(200);
    await http().get('/orders/refund?status=shipped').set('x-user', 'root').expect(403);
    await http().get('/orders/refund?status=paid').set('x-user', 'root').expect(200, 'refunded');
  });

  it('runs every @Can() twice per request when forRoot() is imported twice: import it once', async () => {
    let checks = 0;

    @Policy()
    class CountingPolicy {
      create(_user: User | null) {
        checks++;
        return true;
      }
    }

    @Controller('counted')
    class CountedController {
      @Get()
      @Can(CountingPolicy, 'create')
      create() {
        return 'created';
      }
    }

    @Module({ imports: [AuthorizationModule.forRoot()], controllers: [CountedController] })
    class FeatureModule {}

    @Module({ imports: [AuthorizationModule.forRoot({ policies: [CountingPolicy] }), FeatureModule] })
    class AppModule {}

    app = await createApp(adapter, AppModule);
    await http().get('/counted').expect(200, 'created');
    expect(checks).toBe(2);
  });
});
