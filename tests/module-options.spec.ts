import {
  Controller,
  Get,
  Injectable,
  Logger,
  Module,
  type CanActivate,
  type ExecutionContext,
  type INestApplication,
} from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import {
  AuthorizationGuard,
  AuthorizationModule,
  AuthorizationService,
  Can,
  Policy,
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

async function boot(module: object) {
  const app = (await Test.createTestingModule({ imports: [module as any] }).compile()).createNestApplication();
  await app.listen(0, '127.0.0.1');
  return app;
}

const startupError = (module: object) =>
  boot(module).then(
    async (app) => {
      await app.close();
      return expect.fail('the app started');
    },
    (error: Error) => error.message,
  );

describe('AuthorizationModule options', () => {
  let app: INestApplication | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
    vi.restoreAllMocks();
  });

  describe('forRootAsync() factory results', () => {
    it.each(['isGlobal', 'globalGuard', 'imports'])('fails at startup when the factory returns `%s`', async (key) => {
      @Module({
        imports: [
          AuthorizationModule.forRootAsync({ useFactory: () => ({ [key]: key === 'imports' ? [] : false }) as AuthorizationModuleOptions }),
        ],
      })
      class AppModule {}

      expect(await startupError(AppModule)).toBe(
        `AuthorizationModule: \`${key}\` is in the options the factory returned. It goes at the top level of ` +
          'forRootAsync(), next to useFactory, because it decides what the module registers.',
      );
    });

    it('accepts a structural option returned as undefined', async () => {
      @Module({
        imports: [
          AuthorizationModule.forRootAsync({
            useFactory: () => ({ getUser: () => users.alice, policies: undefined }) as AuthorizationModuleOptions,
            policies: [PostPolicy],
          }),
        ],
        controllers: [PostsController],
      })
      class AppModule {}

      app = await boot(AppModule);
      await request(app.getHttpServer()).get('/posts').expect(200);
    });

    it('fails at startup when getUser is null', async () => {
      @Module({
        imports: [AuthorizationModule.forRootAsync({ useFactory: () => ({ getUser: null }) as unknown as AuthorizationModuleOptions })],
      })
      class AppModule {}

      expect(await startupError(AppModule)).toBe(
        'AuthorizationModule: `getUser` must be a function that returns the current user (or a promise of it).',
      );
    });

    it('fails at startup when forRoot() is given a getUser that is not a function', async () => {
      @Module({ imports: [AuthorizationModule.forRoot({ getUser: 42 as never })] })
      class AppModule {}

      expect(await startupError(AppModule)).toContain('`getUser` must be a function');
    });

    it('awaits an async factory', async () => {
      @Module({
        imports: [
          AuthorizationModule.forRootAsync({
            useFactory: async (): Promise<AuthorizationModuleOptions> => {
              await Promise.resolve();
              return { getUser: () => users.eve };
            },
            policies: [PostPolicy],
          }),
        ],
        controllers: [PostsController],
      })
      class AppModule {}

      app = await boot(AppModule);
      await request(app.getHttpServer()).get('/posts').expect(403);
    });

    it('accepts useExisting with an options factory another module exports', async () => {
      @Injectable()
      class SharedConfig implements AuthorizationOptionsFactory {
        createAuthorizationOptions(): AuthorizationModuleOptions {
          return { getUser: () => users.alice };
        }
      }

      @Module({ providers: [SharedConfig], exports: [SharedConfig] })
      class ConfigModule {}

      @Module({
        imports: [
          AuthorizationModule.forRootAsync({ imports: [ConfigModule], useExisting: SharedConfig, policies: [PostPolicy] }),
        ],
        controllers: [PostsController],
      })
      class AppModule {}

      app = await boot(AppModule);
      await request(app.getHttpServer()).get('/posts').expect(200);
    });
  });

  describe('what the module registers', () => {
    const appGuards = (module: ReturnType<typeof AuthorizationModule.forRoot>) =>
      (module.providers ?? []).filter((provider) => (provider as { provide?: unknown }).provide === APP_GUARD);

    it('registers AuthorizationGuard as APP_GUARD unless globalGuard is false', () => {
      expect(appGuards(AuthorizationModule.forRoot())).toEqual([{ provide: APP_GUARD, useExisting: AuthorizationGuard }]);
      expect(appGuards(AuthorizationModule.forRoot({ globalGuard: false }))).toEqual([]);
      expect(appGuards(AuthorizationModule.forRootAsync({ useFactory: () => ({}), globalGuard: false }))).toEqual([]);
    });

    it('with globalGuard: false, leaves @Can() unenforced on routes without @UseGuards(AuthorizationGuard)', async () => {
      vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);

      @Module({
        imports: [AuthorizationModule.forRoot({ policies: [PostPolicy], globalGuard: false })],
        controllers: [PostsController],
      })
      class AppModule {}

      app = await boot(AppModule);
      await request(app.getHttpServer()).get('/posts').expect(200, ['ok']);
    });

    it('provides and exports the policies it is given, so other modules can inject them', () => {
      const root = AuthorizationModule.forRoot({ policies: [PostPolicy] });

      expect(root.providers).toContain(PostPolicy);
      expect(root.exports).toContain(PostPolicy);
    });

    it('makes a listed policy injectable in any module while global', async () => {
      @Injectable()
      class UsesPolicy {
        constructor(readonly policy: PostPolicy) {}
      }

      @Module({ providers: [UsesPolicy] })
      class FeatureModule {}

      const moduleRef = await Test.createTestingModule({
        imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] }), FeatureModule],
      }).compile();

      expect(moduleRef.get(UsesPolicy).policy).toBeInstanceOf(PostPolicy);
      await moduleRef.close();
    });

    it('with isGlobal: false, hides AuthorizationService from modules that do not import it', async () => {
      @Injectable()
      class NeedsAuthz {
        constructor(readonly authz: AuthorizationService) {}
      }

      @Module({ providers: [NeedsAuthz] })
      class FeatureModule {}

      await expect(
        Test.createTestingModule({ imports: [AuthorizationModule.forRoot({ isGlobal: false }), FeatureModule] }).compile(),
      ).rejects.toThrow(/NeedsAuthz/);

      @Module({ imports: [AuthorizationModule.forRoot({ isGlobal: false })], providers: [NeedsAuthz] })
      class ImportingModule {}

      const moduleRef = await Test.createTestingModule({ imports: [ImportingModule] }).compile();
      expect(moduleRef.get(NeedsAuthz).authz).toBeInstanceOf(AuthorizationService);
      await moduleRef.close();
    });
  });

  describe('startup reports', () => {
    const errors: string[] = [];
    beforeEach(() => {
      errors.length = 0;
      vi.spyOn(Logger.prototype, 'error').mockImplementation((message: unknown) => {
        errors.push(String(message));
      });
    });

    it('lists the first three handlers of a long report and counts the rest', async () => {
      @Controller('many')
      class ManyController {
        @Get('a')
        @Can(PostPolicy, 'create')
        a() {}

        @Get('b')
        @Can(PostPolicy, 'create')
        b() {}

        @Get('c')
        @Can(PostPolicy, 'create')
        c() {}

        @Get('d')
        @Can(PostPolicy, 'create')
        d() {}

        @Get('e')
        @Can(PostPolicy, 'create')
        e() {}
      }

      @Module({
        imports: [AuthorizationModule.forRoot({ policies: [PostPolicy], globalGuard: false })],
        controllers: [ManyController],
      })
      class AppModule {}

      app = await boot(AppModule);
      expect(errors).toEqual([
        '@Can() is not enforced on ManyController.a, ManyController.b, ManyController.c and 2 more: ' +
          'AuthorizationModule has globalGuard: false, and these handlers have no @UseGuards(AuthorizationGuard).',
      ]);
    });

    it('applies a class-level @Can() to decorated handlers only, not to plain helper methods', async () => {
      @Controller('stats')
      @Can(PostPolicy, 'viewStats')
      class StatsController {
        @Get()
        view() {}

        format() {}
      }

      @Module({
        imports: [AuthorizationModule.forRoot({ policies: [PostPolicy], globalGuard: false })],
        controllers: [StatsController],
      })
      class AppModule {}

      app = await boot(AppModule);
      expect(errors).toEqual([expect.stringMatching(/^@Can\(\) is not enforced on StatsController\.view: /)]);
    });

    it('groups the handlers one misplaced guard affects into one message', async () => {
      @Injectable()
      class JwtAuthGuard implements CanActivate {
        canActivate(_context: ExecutionContext) {
          return true;
        }
      }

      @Module({ providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }] })
      class JwtModule {}

      @Controller('stats')
      class StatsController {
        @Get('a')
        @Can(PostPolicy, 'viewStats')
        a() {}

        @Get('b')
        @Can(PostPolicy, 'exportStats')
        b() {}
      }

      @Module({
        imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] }), JwtModule],
        controllers: [StatsController],
      })
      class AppModule {}

      app = await boot(AppModule);
      expect(errors).toEqual([
        'AuthorizationGuard runs before JwtAuthGuard, so if JwtAuthGuard authenticates, @Can() on ' +
          'StatsController.a, StatsController.b sees every caller as a guest. ' +
          'Nest runs global guards in module import order: import JwtModule before AuthorizationModule.',
      ]);
    });

    it('reports a missing policy before anything else, and does not log', async () => {
      @Policy()
      class GhostPolicy {
        view(_user: User | null) {
          return true;
        }
      }

      @Controller('ghost')
      class GhostController {
        @Get()
        @Can(GhostPolicy, 'view')
        list() {}
      }

      @Module({
        imports: [AuthorizationModule.forRoot({ globalGuard: false })],
        controllers: [GhostController],
      })
      class AppModule {}

      expect(await startupError(AppModule)).toMatch(/^@Can\(GhostPolicy, 'view'\) on GhostController\.list: GhostPolicy is not registered\./);
      expect(errors).toEqual([]);
    });

    it('reports a class that is not a policy with the fix', async () => {
      @Injectable()
      class PlainService {
        view(_user: User | null) {
          return true;
        }
      }

      @Controller('plain')
      class PlainController {
        @Get()
        @Can(PlainService as never, 'view' as never)
        list() {}
      }

      @Module({ imports: [AuthorizationModule.forRoot()], controllers: [PlainController], providers: [PlainService] })
      class AppModule {}

      expect(await startupError(AppModule)).toBe(
        "@Can(PlainService, 'view') on PlainController.list: PlainService is not a policy. " +
          'Decorate it with @Policy() and register it as a provider.',
      );
    });

    it('starts when no handler uses @Can(), leaving a missing policy to the check that names it', async () => {
      @Module({ imports: [AuthorizationModule.forRoot()] })
      class AppModule {}

      app = await boot(AppModule);
      expect(errors).toEqual([]);
      await expect(app.get(AuthorizationService).can(PostPolicy, 'create', users.alice)).rejects.toThrow(
        'PostPolicy is not registered',
      );
    });
  });
});
