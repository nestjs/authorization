import {
  Controller,
  Get,
  Injectable,
  Logger,
  Module,
  Scope,
  UseGuards,
  type CanActivate,
  type ExecutionContext,
  type INestApplication,
} from '@nestjs/common';
import { APP_GUARD, LazyModuleLoader } from '@nestjs/core';
import { Test, type TestingModuleBuilder } from '@nestjs/testing';
import request from 'supertest';
import {
  AUTHORIZATION_MODULE_OPTIONS,
  AuthorizationEvents,
  AuthorizationGuard,
  AuthorizationModule,
  AuthorizationService,
  Can,
  Policy,
  type AuthorizationDeniedEvent,
  type AuthorizationModuleAsyncOptions,
  type AuthorizationModuleOptions,
  type AuthorizationOptionsFactory,
} from '../lib/index.js';
import { PostPolicy, users, type User } from './fixtures.js';

@Controller('posts')
class PostsController {
  @Get()
  @Can(PostPolicy, 'create')
  list() {
    return ['ok'];
  }
}

/** Where a real app would keep the current user (a CLS store, a request context). */
@Injectable()
class CurrentUserStore {
  user: User | null = null;
}

@Module({ providers: [CurrentUserStore], exports: [CurrentUserStore] })
class CurrentUserModule {}

async function boot(
  module: object,
  override?: (builder: TestingModuleBuilder) => TestingModuleBuilder,
  /** Runs before `init()`, like the lines between `NestFactory.create()` and `listen()` in main.ts. */
  setup?: (app: INestApplication) => void,
) {
  let builder = Test.createTestingModule({ imports: [module as any] });
  if (override) {
    builder = override(builder);
  }
  const app = (await builder.compile()).createNestApplication();
  setup?.(app);
  await app.listen(0, '127.0.0.1');
  return app;
}

describe('AuthorizationModule', () => {
  let app: INestApplication | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
    vi.restoreAllMocks();
  });

  describe('forRootAsync()', () => {
    it('takes getUser from a factory that injects providers, and policies at the top level', async () => {
      @Module({
        imports: [
          AuthorizationModule.forRootAsync({
            imports: [CurrentUserModule],
            inject: [CurrentUserStore],
            useFactory: (store: CurrentUserStore): AuthorizationModuleOptions => ({ getUser: () => store.user }),
            policies: [PostPolicy],
          }),
        ],
        controllers: [PostsController],
      })
      class AppModule {}

      app = await boot(AppModule);
      const store = app.get(CurrentUserStore);
      await request(app.getHttpServer()).get('/posts').expect(401);
      store.user = users.eve;
      await request(app.getHttpServer()).get('/posts').expect(403);
      store.user = users.alice;
      await request(app.getHttpServer()).get('/posts').expect(200);
    });

    it('accepts an options class', async () => {
      @Injectable()
      class AuthorizationConfig implements AuthorizationOptionsFactory {
        createAuthorizationOptions(): AuthorizationModuleOptions {
          return { getUser: () => users.alice };
        }
      }

      // What a library wrapping the module passes through.
      const options: AuthorizationModuleAsyncOptions = { useClass: AuthorizationConfig, policies: [PostPolicy] };

      @Module({ imports: [AuthorizationModule.forRootAsync(options)], controllers: [PostsController] })
      class AppModule {}

      app = await boot(AppModule);
      await request(app.getHttpServer()).get('/posts').expect(200);
    });

    it('fails at startup when the factory returns an option that belongs next to it', async () => {
      @Module({
        imports: [
          AuthorizationModule.forRootAsync({
            useFactory: () => ({ getUser: () => users.alice, policies: [PostPolicy] }) as AuthorizationModuleOptions,
          }),
        ],
      })
      class AppModule {}

      await expect(boot(AppModule)).rejects.toThrow(
        'AuthorizationModule: `policies` is in the options the factory returned. It goes at the top level of ' +
          'forRootAsync(), next to useFactory, because it decides what the module registers.',
      );
    });

    it('fails at startup when getUser is not a function', async () => {
      @Module({
        imports: [
          AuthorizationModule.forRootAsync({ useFactory: () => ({ getUser: 'user' }) as unknown as AuthorizationModuleOptions }),
        ],
      })
      class AppModule {}

      await expect(boot(AppModule)).rejects.toThrow(
        'AuthorizationModule: `getUser` must be a function that returns the current user (or a promise of it).',
      );
    });
  });

  describe('imports', () => {
    @Injectable()
    class Flags {
      creating = true;
    }

    @Module({ providers: [Flags], exports: [Flags] })
    class FlagsModule {}

    /** Listed in `policies`, so it lives in the authorization module, which must import Flags. */
    @Policy()
    class FlaggedPolicy {
      constructor(private readonly flags: Flags) {}

      create(user: User | null) {
        return !!user && this.flags.creating;
      }
    }

    @Controller('flagged')
    class FlaggedController {
      @Get()
      @Can(FlaggedPolicy, 'create')
      list() {}
    }

    it('forRoot() takes the modules its policies inject from', async () => {
      @Module({
        imports: [
          AuthorizationModule.forRoot({ policies: [FlaggedPolicy], imports: [FlagsModule], getUser: () => users.alice }),
        ],
        controllers: [FlaggedController],
      })
      class AppModule {}

      app = await boot(AppModule);
      await request(app.getHttpServer()).get('/flagged').expect(200);
      app.get(Flags).creating = false;
      await request(app.getHttpServer()).get('/flagged').expect(403);
    });

    it("forRootAsync()'s imports serve both the factory and the policies", async () => {
      @Module({
        imports: [
          AuthorizationModule.forRootAsync({
            imports: [FlagsModule, CurrentUserModule],
            inject: [CurrentUserStore],
            useFactory: (store: CurrentUserStore): AuthorizationModuleOptions => ({ getUser: () => store.user }),
            policies: [FlaggedPolicy],
          }),
        ],
        controllers: [FlaggedController],
      })
      class AppModule {}

      app = await boot(AppModule);
      await request(app.getHttpServer()).get('/flagged').expect(401);
      app.get(CurrentUserStore).user = users.alice;
      await request(app.getHttpServer()).get('/flagged').expect(200);
    });
  });

  it('is global unless isGlobal is false', () => {
    expect(AuthorizationModule.forRoot().global).toBe(true);
    expect(AuthorizationModule.forRoot({ isGlobal: false }).global).toBe(false);
    expect(AuthorizationModule.forRootAsync({ useFactory: () => ({}), isGlobal: false }).global).toBe(false);
  });

  it('treats an option passed as undefined like one left out', async () => {
    // A wrapper passing its own unset settings through must not drop the guard.
    const settings: { isGlobal?: boolean; globalGuard?: boolean } = { isGlobal: undefined, globalGuard: undefined };
    const root = AuthorizationModule.forRoot({ policies: [PostPolicy], ...settings });
    expect(root.global).toBe(true);
    expect(AuthorizationModule.forRootAsync({ useFactory: () => ({}), ...settings }).global).toBe(true);

    @Module({ imports: [root], controllers: [PostsController] })
    class AppModule {}

    app = await boot(AppModule);
    await request(app.getHttpServer()).get('/posts').expect(401); // @Can() enforced by the global guard
  });

  it('awaits an async getUser', async () => {
    @Module({
      imports: [AuthorizationModule.forRoot({ policies: [PostPolicy], getUser: async () => users.alice })],
      controllers: [PostsController],
    })
    class AppModule {}

    app = await boot(AppModule);
    await request(app.getHttpServer()).get('/posts').expect(200);
  });

  it("treats Passport's `request.user = false` (optional authentication, no credentials) as a guest", async () => {
    /** Passport's AuthGuard with `handleRequest(err, user) { return user; }` leaves `false` for anonymous callers. */
    @Injectable()
    class OptionalJwtAuthGuard implements CanActivate {
      canActivate(context: ExecutionContext) {
        const request = context.switchToHttp().getRequest();
        request.user = users[request.headers['x-user']] ?? false;
        return true;
      }
    }

    @Module({
      imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] })],
      controllers: [PostsController],
      providers: [{ provide: APP_GUARD, useClass: OptionalJwtAuthGuard }],
    })
    class AppModule {}

    app = await boot(AppModule);
    const events: AuthorizationDeniedEvent[] = [];
    app.get(AuthorizationEvents).events$.subscribe((event) => events.push(event));
    await request(app.getHttpServer()).get('/posts').expect(401); // a guest: sign in, not a 500 or a 403
    await request(app.getHttpServer()).get('/posts').set('x-user', 'alice').expect(200);
    expect(events.map(({ user, reason }) => ({ user, reason }))).toEqual([{ user: null, reason: 'unauthenticated' }]);
  });

  it('completes events$ when the app shuts down', async () => {
    @Module({ imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] })], controllers: [PostsController] })
    class AppModule {}

    const closing = await boot(AppModule);
    const complete = vi.fn();
    closing.get(AuthorizationEvents).events$.subscribe({ complete });
    await closing.close();
    expect(complete).toHaveBeenCalledTimes(1);
  });

  describe('testing an app', () => {
    @Module({ imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] })], controllers: [PostsController] })
    class AppModule {}

    it('overriding AUTHORIZATION_MODULE_OPTIONS sets the user @Can() sees', async () => {
      app = await boot(AppModule, (builder) =>
        builder.overrideProvider(AUTHORIZATION_MODULE_OPTIONS).useValue({ getUser: () => users.alice }),
      );
      await request(app.getHttpServer()).get('/posts').expect(200);
    });

    it('overriding a policy replaces what every check runs against', async () => {
      app = await boot(AppModule, (builder) =>
        builder.overrideProvider(PostPolicy).useValue({ create: () => true }),
      );
      await request(app.getHttpServer()).get('/posts').expect(200);
      expect(await app.get(AuthorizationService).can(PostPolicy, 'create', null)).toBe(true);
    });

    it('overriding a policy with a class works too', async () => {
      class DenyAll {
        create() {
          return false;
        }
      }
      app = await boot(AppModule, (builder) =>
        builder
          .overrideProvider(PostPolicy)
          .useClass(DenyAll)
          .overrideProvider(AUTHORIZATION_MODULE_OPTIONS)
          .useValue({ getUser: () => users.alice }),
      );
      await request(app.getHttpServer()).get('/posts').expect(403);
    });
  });

  it('finds policies registered in lazily loaded modules', async () => {
    @Policy()
    class ReportPolicy {
      export(user: User | null) {
        return !!user?.roles.includes('exporter');
      }
    }

    @Module({ providers: [ReportPolicy] })
    class ReportsModule {}

    const moduleRef = await Test.createTestingModule({ imports: [AuthorizationModule.forRoot()] }).compile();
    await moduleRef.init();
    const authz = moduleRef.get(AuthorizationService);
    await expect(authz.can(ReportPolicy, 'export', users.xavier)).rejects.toThrow('ReportPolicy is not registered');

    await moduleRef.get(LazyModuleLoader).load(() => ReportsModule);
    expect(await authz.can(ReportPolicy, 'export', users.xavier)).toBe(true);
    await moduleRef.close();
  });

  describe('startup checks', () => {
    const errors: string[] = [];
    beforeEach(() => {
      errors.length = 0;
      vi.spyOn(Logger.prototype, 'error').mockImplementation((message: unknown) => {
        errors.push(String(message));
      });
    });

    it('fails on an ability the policy does not have, and on class-level @Can() once', async () => {
      @Policy()
      class UnregisteredPolicy {
        view(_user: User | null) {
          return true;
        }
      }

      @Controller('broken')
      @Can(UnregisteredPolicy, 'view')
      class BrokenController {
        @Get('a')
        @Can(PostPolicy, 'publish' as never)
        a() {}

        @Get('b')
        b() {}

        // Every object has a toString(); it is still not an ability.
        @Get('c')
        @Can(PostPolicy, 'toString' as never)
        c() {}

        helper() {}
      }

      @Module({ imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] })], controllers: [BrokenController] })
      class AppModule {}

      const failure = await boot(AppModule).catch((error: Error) => error);
      expect((failure as Error).message.split('\n')).toEqual([
        "@Can(UnregisteredPolicy, 'view') on BrokenController: UnregisteredPolicy is not registered. " +
          'Add it to the providers of a module, or to AuthorizationModule.forRoot({ policies }).',
        "@Can(PostPolicy, 'publish') on BrokenController.a: PostPolicy has no ability 'publish'.",
        "@Can(PostPolicy, 'toString') on BrokenController.c: PostPolicy has no ability 'toString'.",
      ]);
    });

    it('checks @Can() on providers too (resolvers, gateways)', async () => {
      @Policy()
      class UnregisteredPolicy {
        view(_user: User | null) {
          return true;
        }
      }

      @Injectable()
      class ReportsResolver {
        @Can(UnregisteredPolicy, 'view')
        report() {}
      }

      @Module({ imports: [AuthorizationModule.forRoot()], providers: [ReportsResolver] })
      class AppModule {}

      await expect(boot(AppModule)).rejects.toThrow("@Can(UnregisteredPolicy, 'view') on ReportsResolver.report");
    });

    it('fails on a request-scoped or transient policy, or one that depends on a request-scoped provider', async () => {
      @Policy()
      class ScopedPolicy {
        view(_user: User | null) {
          return true;
        }
      }

      @Injectable({ scope: Scope.REQUEST })
      class RequestClock {}

      @Policy()
      class ClockPolicy {
        constructor(readonly clock: RequestClock) {}
        view(_user: User | null) {
          return true;
        }
      }

      const startupError = async (provider: object) => {
        @Module({ imports: [AuthorizationModule.forRoot()], providers: [provider as any] })
        class AppModule {}
        return boot(AppModule).then(
          () => expect.fail('the app started'),
          (error: Error) => error.message,
        );
      };
      const fix = 'Policies must be singletons: pass what varies per request to the ability as an argument.';

      expect(await startupError({ provide: ScopedPolicy, useClass: ScopedPolicy, scope: Scope.REQUEST })).toBe(
        `ScopedPolicy is request-scoped. ${fix}`,
      );
      expect(await startupError({ provide: ScopedPolicy, useClass: ScopedPolicy, scope: Scope.TRANSIENT })).toBe(
        `ScopedPolicy is transient. ${fix}`,
      );

      @Module({ imports: [AuthorizationModule.forRoot()], providers: [RequestClock, ClockPolicy] })
      class ClockModule {}
      await expect(boot(ClockModule)).rejects.toThrow(`ClockPolicy depends on a request-scoped provider. ${fix}`);
    });

    describe('guard order with other authentication guards (by name)', () => {
      /** Stands in for JwtAuthGuard, Passport's AuthGuard(): no brand, so only the name says it authenticates. */
      @Injectable()
      class HeaderAuthGuard implements CanActivate {
        canActivate(context: ExecutionContext) {
          const request = context.switchToHttp().getRequest();
          request.user = users[request.headers['x-user']];
          return true;
        }
      }

      @Module({ providers: [{ provide: APP_GUARD, useClass: HeaderAuthGuard }] })
      class HeaderAuthModule {}

      it('says nothing when authentication runs first', async () => {
        @Module({
          imports: [HeaderAuthModule, AuthorizationModule.forRoot({ policies: [PostPolicy] })],
          controllers: [PostsController],
        })
        class AppModule {}

        app = await boot(AppModule);
        expect(errors).toEqual([]);
        await request(app.getHttpServer()).get('/posts').set('x-user', 'alice').expect(200);
      });

      it('logs an error when a global guard that looks like authentication runs after it', async () => {
        @Module({
          imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] }), HeaderAuthModule],
          controllers: [PostsController],
        })
        class AppModule {}

        app = await boot(AppModule);
        expect(errors).toEqual([
          'AuthorizationGuard runs before HeaderAuthGuard, so if HeaderAuthGuard authenticates, @Can() on ' +
            'PostsController.list sees every caller as a guest. ' +
            'Nest runs global guards in module import order: import HeaderAuthModule before AuthorizationModule.',
        ]);
        // The symptom the message describes.
        await request(app.getHttpServer()).get('/posts').set('x-user', 'alice').expect(401);
      });

      it('goes by names that mean authentication, not by Author, Authority, Authz or Authorisation', async () => {
        /** Whether a guard of this name, applied after the global AuthorizationGuard, gets logged. */
        const logged = async (name: string) => {
          const Guard = { [name]: class implements CanActivate { canActivate() { return true; } } }[name];
          Injectable()(Guard);

          @Controller('posts')
          @UseGuards(Guard)
          class GuardedController {
            @Get()
            @Can(PostPolicy, 'create')
            list() {}
          }

          @Module({ imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] })], controllers: [GuardedController] })
          class AppModule {}

          errors.length = 0;
          await (await boot(AppModule)).close();
          return errors.length > 0;
        };

        for (const name of ['AuthorGuard', 'CoAuthorsGuard', 'AuthorityGuard', 'AuthzGuard', 'AuthorisationGuard', 'RolesGuard']) {
          expect({ name, logged: await logged(name) }).toEqual({ name, logged: false });
        }

        for (const name of ['AuthGuard', 'JwtAuthGuard', 'OAuth2Guard', 'AuthenticatedGuard', 'JwtGuard', 'ApiKeyGuard']) {
          expect({ name, logged: await logged(name) }).toEqual({ name, logged: true });
        }
      });

      it('logs an error when @UseGuards() authenticates after the global AuthorizationGuard', async () => {
        @Controller('posts')
        @UseGuards(HeaderAuthGuard)
        class GuardedController {
          @Get()
          @Can(PostPolicy, 'create')
          list() {}
        }

        @Module({ imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] })], controllers: [GuardedController] })
        class AppModule {}

        app = await boot(AppModule);
        expect(errors).toEqual([
          'AuthorizationGuard runs before HeaderAuthGuard, so if HeaderAuthGuard authenticates, @Can() on ' +
            'GuardedController.list sees every caller as a guest. ' +
            'Global guards run before @UseGuards(): set globalGuard: false and write @UseGuards(HeaderAuthGuard, AuthorizationGuard).',
        ]);
      });

      it('logs an error for a request-scoped global guard that looks like authentication, whatever the import order', async () => {
        // Nest runs request-scoped global guards after every singleton one, so
        // importing the module first does not put this guard first.
        @Module({ providers: [{ provide: APP_GUARD, useClass: HeaderAuthGuard, scope: Scope.REQUEST }] })
        class RequestScopedAuthModule {}

        @Module({
          imports: [RequestScopedAuthModule, AuthorizationModule.forRoot({ policies: [PostPolicy] })],
          controllers: [PostsController],
        })
        class AppModule {}

        app = await boot(AppModule);
        expect(errors).toEqual([
          'AuthorizationGuard runs before HeaderAuthGuard, so if HeaderAuthGuard authenticates, @Can() on ' +
            'PostsController.list sees every caller as a guest. ' +
            'Nest runs request-scoped global guards after the singleton ones, whatever the import order: make ' +
            'HeaderAuthGuard a singleton (a guard reads the request from its ExecutionContext), or set ' +
            'globalGuard: false and write @UseGuards(HeaderAuthGuard, AuthorizationGuard).',
        ]);
        // The symptom the message describes.
        await request(app.getHttpServer()).get('/posts').set('x-user', 'alice').expect(401);
      });

      it('cannot see guards added with app.useGlobalGuards(), which Nest runs after every APP_GUARD', async () => {
        @Module({ imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] })], controllers: [PostsController] })
        class AppModule {}

        app = await boot(AppModule, undefined, (a) => a.useGlobalGuards(new HeaderAuthGuard()));
        expect(errors).toEqual([]);
        // What the README warns about: authentication runs after AuthorizationGuard, so the policy sees a guest.
        await request(app.getHttpServer()).get('/posts').set('x-user', 'alice').expect(401);
      });

      it('with globalGuard: false, @UseGuards(auth, AuthorizationGuard) enforces @Can() in any module', async () => {
        @Controller('posts')
        @UseGuards(HeaderAuthGuard, AuthorizationGuard)
        class GuardedController {
          @Get()
          @Can(PostPolicy, 'create')
          list() {}
        }

        @Module({ controllers: [GuardedController] })
        class PostsModule {}

        @Module({
          imports: [AuthorizationModule.forRoot({ policies: [PostPolicy], globalGuard: false }), PostsModule],
        })
        class AppModule {}

        app = await boot(AppModule);
        expect(errors).toEqual([]);
        await request(app.getHttpServer()).get('/posts').set('x-user', 'alice').expect(200);
        await request(app.getHttpServer()).get('/posts').set('x-user', 'eve').expect(403);
      });

      it('with globalGuard: false, logs an error for @Can() that no guard enforces', async () => {
        @Module({
          imports: [AuthorizationModule.forRoot({ policies: [PostPolicy], globalGuard: false })],
          controllers: [PostsController],
        })
        class AppModule {}

        app = await boot(AppModule);
        expect(errors).toEqual([
          '@Can() is not enforced on PostsController.list: AuthorizationModule has globalGuard: false, ' +
            'and these handlers have no @UseGuards(AuthorizationGuard).',
        ]);
      });
    });

    describe("guard order with @nestjs/authentication's guard (by brand)", () => {
      const brand: unique symbol = Symbol.for('@nestjs/authentication:guard');

      /** Stands in for AuthenticationGuard: it carries the brand @nestjs/authentication puts on it. */
      @Injectable()
      class AuthenticationGuard implements CanActivate {
        static readonly [brand] = true;

        canActivate(context: ExecutionContext) {
          const request = context.switchToHttp().getRequest();
          request.user = users[request.headers['x-user']];
          return true;
        }
      }

      /** Registers it the way AuthenticationModule does. */
      @Module({ providers: [AuthenticationGuard, { provide: APP_GUARD, useExisting: AuthenticationGuard }] })
      class AuthenticationModule {}

      @Controller('posts')
      @UseGuards(AuthenticationGuard)
      class GuardedController {
        @Get()
        @Can(PostPolicy, 'create')
        list() {}
      }

      const startupError = (module: object) =>
        boot(module).then(
          () => expect.fail('the app started'),
          (error: Error) => error.message,
        );

      it('says nothing when AuthenticationModule is imported first', async () => {
        @Module({
          imports: [AuthenticationModule, AuthorizationModule.forRoot({ policies: [PostPolicy] })],
          controllers: [PostsController],
        })
        class AppModule {}

        app = await boot(AppModule);
        expect(errors).toEqual([]);
        await request(app.getHttpServer()).get('/posts').set('x-user', 'alice').expect(200);
      });

      it('fails the startup when AuthenticationModule is imported after AuthorizationModule', async () => {
        @Module({
          imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] }), AuthenticationModule],
          controllers: [PostsController],
        })
        class AppModule {}

        expect(await startupError(AppModule)).toBe(
          'AuthorizationGuard runs before AuthenticationGuard, so @Can() on PostsController.list would see every caller as a guest. ' +
            'Nest runs global guards in module import order: import AuthenticationModule before AuthorizationModule.',
        );
        expect(errors).toEqual([]);
      });

      it('fails the startup for a request-scoped AuthenticationGuard, whatever the import order', async () => {
        @Module({ providers: [{ provide: APP_GUARD, useClass: AuthenticationGuard, scope: Scope.REQUEST }] })
        class RequestScopedAuthenticationModule {}

        @Module({
          imports: [RequestScopedAuthenticationModule, AuthorizationModule.forRoot({ policies: [PostPolicy] })],
          controllers: [PostsController],
        })
        class AppModule {}

        expect(await startupError(AppModule)).toBe(
          'AuthorizationGuard runs before AuthenticationGuard, so @Can() on PostsController.list would see every caller as a guest. ' +
            'Nest runs request-scoped global guards after the singleton ones, whatever the import order: make ' +
            'AuthenticationGuard a singleton (a guard reads the request from its ExecutionContext), or set ' +
            'globalGuard: false and write @UseGuards(AuthenticationGuard, AuthorizationGuard).',
        );
      });

      it('fails the startup when @UseGuards(AuthenticationGuard) runs after the global AuthorizationGuard', async () => {
        @Module({ imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] })], controllers: [GuardedController] })
        class AppModule {}

        expect(await startupError(AppModule)).toBe(
          'AuthorizationGuard runs before AuthenticationGuard, so @Can() on GuardedController.list would see every caller as a guest. ' +
            'Global guards run before @UseGuards(): set globalGuard: false and write @UseGuards(AuthenticationGuard, AuthorizationGuard).',
        );
      });

      it('fails the startup when @UseGuards() lists AuthorizationGuard first', async () => {
        @Controller('posts')
        @UseGuards(AuthorizationGuard, AuthenticationGuard)
        class BackwardsController {
          @Get()
          @Can(PostPolicy, 'create')
          list() {}
        }

        @Module({
          imports: [AuthorizationModule.forRoot({ policies: [PostPolicy], globalGuard: false })],
          controllers: [BackwardsController],
        })
        class AppModule {}

        expect(await startupError(AppModule)).toBe(
          'AuthorizationGuard runs before AuthenticationGuard, so @Can() on BackwardsController.list would see every caller as a guest. ' +
            '@UseGuards() runs guards in the order listed: write @UseGuards(AuthenticationGuard, AuthorizationGuard).',
        );
      });

      it('with globalGuard: false, accepts @UseGuards(AuthenticationGuard, AuthorizationGuard)', async () => {
        @Controller('posts')
        @UseGuards(AuthenticationGuard, AuthorizationGuard)
        class OrderedController {
          @Get()
          @Can(PostPolicy, 'create')
          list() {}
        }

        @Module({
          imports: [AuthorizationModule.forRoot({ policies: [PostPolicy], globalGuard: false })],
          controllers: [OrderedController],
        })
        class AppModule {}

        app = await boot(AppModule);
        expect(errors).toEqual([]);
        await request(app.getHttpServer()).get('/posts').set('x-user', 'alice').expect(200);
      });

      it('accepts another AuthenticationGuard after AuthorizationGuard once one has run before it', async () => {
        @Module({
          imports: [AuthenticationModule, AuthorizationModule.forRoot({ policies: [PostPolicy] })],
          controllers: [GuardedController],
        })
        class AppModule {}

        app = await boot(AppModule);
        expect(errors).toEqual([]);
        await request(app.getHttpServer()).get('/posts').set('x-user', 'alice').expect(200);
      });

      it('goes by the brand, which subclasses inherit, not by the class name', async () => {
        @Injectable()
        class SessionGate extends AuthenticationGuard {}

        @Module({ providers: [{ provide: APP_GUARD, useClass: SessionGate }] })
        class SessionGateModule {}

        @Module({
          imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] }), SessionGateModule],
          controllers: [PostsController],
        })
        class BrandedAppModule {}

        expect(await startupError(BrandedAppModule)).toBe(
          'AuthorizationGuard runs before SessionGate, so @Can() on PostsController.list would see every caller as a guest. ' +
            'Nest runs global guards in module import order: import SessionGateModule before AuthorizationModule.',
        );

        // Named like the real one, but without the brand: only the name
        // heuristic applies, and it logs instead of failing.
        {
          @Injectable()
          class AuthenticationGuard implements CanActivate {
            canActivate() {
              return true;
            }
          }

          @Module({ providers: [{ provide: APP_GUARD, useClass: AuthenticationGuard }] })
          class HandWrittenAuthModule {}

          @Module({
            imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] }), HandWrittenAuthModule],
            controllers: [PostsController],
          })
          class UnbrandedAppModule {}

          app = await boot(UnbrandedAppModule);
          expect(errors).toEqual([
            'AuthorizationGuard runs before AuthenticationGuard, so if AuthenticationGuard authenticates, @Can() on ' +
              'PostsController.list sees every caller as a guest. ' +
              'Nest runs global guards in module import order: import HandWrittenAuthModule before AuthorizationModule.',
          ]);
        }
      });
    });

    it("recognizes AuthorizationGuard by its registry brand, so another copy of the package's guard counts", async () => {
      const authorizationBrand: unique symbol = Symbol.for('@nestjs/authorization:guard');

      /** What `AuthorizationGuard` looks like when it comes from a second copy of this package. */
      @Injectable()
      class OtherCopyAuthorizationGuard implements CanActivate {
        static readonly [authorizationBrand] = true;
        canActivate() {
          return true;
        }
      }

      @Controller('posts')
      @UseGuards(OtherCopyAuthorizationGuard)
      class GuardedController {
        @Get()
        @Can(PostPolicy, 'create')
        list() {}
      }

      @Module({
        imports: [AuthorizationModule.forRoot({ policies: [PostPolicy], globalGuard: false })],
        controllers: [GuardedController],
      })
      class AppModule {}

      app = await boot(AppModule);
      expect(errors).toEqual([]); // not reported as "@Can() is not enforced"
    });
  });
});
