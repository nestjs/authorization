/**
 * `AuthorizationError.status` marks a denial as the caller's fault, so `@nestjs/resilience`
 * classifies it without importing it: a denied request is not retried, not counted against
 * a circuit breaker and not replaced by a fallback, in whatever order the two modules'
 * global interceptors run.
 */
import { Controller, Get, Injectable, Logger, Module, Query, type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import { CircuitBreaker, Fallback, ResilienceEvents, ResilienceModule, Retry, type ResilienceEvent } from '@nestjs/resilience';
import { AuthorizationModule, AuthorizationService, Can, Policy } from '../lib/index.js';
import { users, type User } from './fixtures.js';

@Policy()
class ReportPolicy {
  export(user: User | null) {
    return !!user?.roles.includes('exporter');
  }
}

@Injectable()
class ReportsService {
  calls = 0;

  constructor(private readonly authorizationService: AuthorizationService) {}

  async export(user: User | null, fail: boolean) {
    this.calls++;
    await this.authorizationService.authorize(ReportPolicy, 'export', user);
    if (fail) {
      throw new Error('warehouse is down');
    }
    return { csv: 'views\n42' };
  }
}

@Controller('reports')
class ReportsController {
  constructor(private readonly reportsService: ReportsService) {}

  @Get('export')
  @Can.Anyone()
  @CircuitBreaker({ name: 'warehouse', minimumCalls: 2, slidingWindow: { type: 'count', size: 2 }, failureRateThreshold: 50 })
  export(@Query('user') name: string | undefined, @Query('fail') fail?: string) {
    return this.reportsService.export(name ? users[name] : null, fail === '1');
  }

  @Get('backup')
  @Can.Anyone()
  @Retry({ attempts: 3, backoff: { delay: 1 } })
  @Fallback(() => ({ csv: 'cached' }))
  backup(@Query('user') name: string | undefined, @Query('fail') fail?: string) {
    return this.reportsService.export(name ? users[name] : null, fail === '1');
  }
}

const orders = {
  'ResilienceModule first': [ResilienceModule.forRoot(), AuthorizationModule.forRoot({ policies: [ReportPolicy] })],
  'AuthorizationModule first': [AuthorizationModule.forRoot({ policies: [ReportPolicy] }), ResilienceModule.forRoot()],
};

describe.each(adapters.map((a) => a.name))('with @nestjs/resilience (%s)', (adapter) => {
  describe.each(Object.entries(orders))('%s', (_order, imports) => {
    @Module({ imports, controllers: [ReportsController], providers: [ReportsService] })
    class AppModule {}

    let app: INestApplication;
    const events: ResilienceEvent[] = [];
    const http = () => request(app.getHttpServer());

    beforeAll(async () => {
      vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
      vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
      app = await createApp(adapter, AppModule);
      app.get(ResilienceEvents).events$.subscribe((event) => events.push(event));
    });
    afterAll(async () => {
      await app.close();
      vi.restoreAllMocks();
    });
    beforeEach(() => {
      events.length = 0;
      app.get(ReportsService).calls = 0;
    });

    it('answers a denial once, with its own status: no retry, no fallback', async () => {
      await http().get('/reports/backup').query({ user: 'alice' }).expect(403, { message: 'Forbidden', statusCode: 403 });
      await http().get('/reports/backup').expect(401, { message: 'Unauthorized', statusCode: 401 });

      expect(app.get(ReportsService).calls).toBe(2);
      expect(events).toEqual([]);
    });

    it('does not count denials against the circuit breaker', async () => {
      for (let i = 0; i < 5; i++) {
        await http().get('/reports/export').query({ user: 'alice' }).expect(403);
      }

      await http().get('/reports/export').query({ user: 'xavier' }).expect(200, { csv: 'views\n42' });
      expect(events.filter(({ type }) => type.startsWith('circuit'))).toEqual([]);
    });

    it('still retries a failure of the permitted caller, then falls back', async () => {
      await http().get('/reports/backup').query({ user: 'xavier', fail: '1' }).expect(200, { csv: 'cached' });

      expect(app.get(ReportsService).calls).toBe(3);
      expect(events.filter(({ type }) => type === 'retry')).toHaveLength(2);
    });

    it("still counts the permitted caller's failures, which open the breaker", async () => {
      // The window holds the earlier success on this route and this failure: 50 %.
      await http().get('/reports/export').query({ user: 'xavier', fail: '1' }).expect(500);
      await http().get('/reports/export').query({ user: 'xavier' }).expect(503);

      expect(events.map(({ type }) => type)).toEqual(['circuit-open', 'circuit-rejected']);
    });
  });
});
