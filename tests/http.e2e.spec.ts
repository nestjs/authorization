import {
  Catch,
  Controller,
  Get,
  HttpException,
  Injectable,
  Logger,
  Module,
  NotFoundException,
  Req,
  type ArgumentsHost,
  type CanActivate,
  type ExceptionFilter,
  type ExecutionContext,
  type INestApplication,
} from '@nestjs/common';
import { APP_FILTER, APP_GUARD, HttpAdapterHost } from '@nestjs/core';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import {
  AuthorizationError,
  AuthorizationService,
  AuthorizationModule,
  Can,
  Policy,
} from '../lib/index.js';
import { users, type User } from './fixtures.js';

@Policy()
class ReportPolicy {
  // Typed `User` where `User | null` was due, as a JavaScript policy or a cast would leave it.
  view(user: User | null) {
    return (user as User).roles.includes('editor');
  }

  export(_user: User | null): boolean {
    throw new Error('flags service is down');
  }

  archive(user: User | null) {
    return !!user?.roles.includes('admin');
  }
}

@Injectable()
class HeaderAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    request.user = users[request.headers['x-user']];
    return true;
  }
}

@Injectable()
class ReportsService {
  constructor(private readonly authorizationService: AuthorizationService) {}

  async archive(user: User | null) {
    await this.authorizationService.authorize(ReportPolicy, 'archive', user);
    return { archived: true };
  }
}

@Controller('reports')
class ReportsController {
  constructor(private readonly reportsService: ReportsService) {}

  @Get('view')
  @Can(ReportPolicy, 'view')
  view() {
    return { views: 1 };
  }

  @Get('export')
  @Can(ReportPolicy, 'export')
  export() {
    return {};
  }

  @Get('archive')
  archive(@Req() req: { user?: User }) {
    return this.reportsService.archive(req.user ?? null);
  }

  @Get('missing')
  missing() {
    throw new NotFoundException('No such report');
  }
}

/** What a logging filter sees: the transport's exception, with the denial as its cause. */
const logged: { status: number; cause: unknown }[] = [];

@Catch(HttpException)
class CauseLoggingFilter implements ExceptionFilter {
  constructor(private readonly adapterHost: HttpAdapterHost) {}

  catch(exception: HttpException, host: ArgumentsHost) {
    logged.push({ status: exception.getStatus(), cause: exception.cause });
    this.adapterHost.httpAdapter.reply(host.switchToHttp().getResponse(), exception.getResponse(), exception.getStatus());
  }
}

@Module({
  imports: [AuthorizationModule.forRoot({ policies: [ReportPolicy] })],
  controllers: [ReportsController],
  providers: [
    ReportsService,
    { provide: APP_GUARD, useClass: HeaderAuthGuard },
    { provide: APP_FILTER, useClass: CauseLoggingFilter },
  ],
})
class ReportsAppModule {}

describe.each(adapters.map((a) => a.name))('HTTP denials and failures (%s)', (adapter) => {
  let app: INestApplication;

  beforeAll(async () => {
    // The guest warning and the 500's stack trace are expected here.
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    app = await createApp(adapter, ReportsAppModule);
  });
  afterAll(async () => {
    await app.close();
    vi.restoreAllMocks();
  });
  beforeEach(() => {
    logged.length = 0;
  });

  it('answers 401 when a @Can() ability dereferences a guest, and still checks signed-in users', async () => {
    await request(app.getHttpServer()).get('/reports/view').expect(401, { message: 'Unauthorized', statusCode: 401 });
    await request(app.getHttpServer()).get('/reports/view').set('x-user', 'alice').expect(403);
    await request(app.getHttpServer()).get('/reports/view').set('x-user', 'eve').expect(200, { views: 1 });
  });

  it('answers 500 when an ability fails, for guests and users alike: an outage is not a denial', async () => {
    await request(app.getHttpServer()).get('/reports/export').expect(500);
    await request(app.getHttpServer()).get('/reports/export').set('x-user', 'alice').expect(500);
  });

  it('hands exception filters the AuthorizationError as the cause, for @Can() and authorize() alike', async () => {
    await request(app.getHttpServer()).get('/reports/view').set('x-user', 'alice').expect(403);
    await request(app.getHttpServer()).get('/reports/archive').expect(401);
    await request(app.getHttpServer()).get('/reports/archive').set('x-user', 'root').expect(200, { archived: true });

    expect(logged).toEqual([
      { status: 403, cause: expect.any(AuthorizationError) },
      { status: 401, cause: expect.any(AuthorizationError) },
    ]);
    expect(logged.map(({ cause }) => (cause as AuthorizationError).ability)).toEqual(['view', 'archive']);
  });

  it('leaves the HTTP exceptions handlers throw themselves untouched', async () => {
    await request(app.getHttpServer())
      .get('/reports/missing')
      .expect(404, { message: 'No such report', error: 'Not Found', statusCode: 404 });
    expect(logged).toEqual([{ status: 404, cause: undefined }]);
  });

});
