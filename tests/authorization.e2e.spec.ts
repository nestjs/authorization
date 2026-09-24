import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import { AuthorizationEvents, type AuthorizationDeniedEvent } from '../lib/index.js';
import { AppModule, MisconfiguredAppModule, users } from './fixtures.js';

const UNAUTHORIZED = { message: 'Unauthorized', statusCode: 401 };
const FORBIDDEN = { message: 'Forbidden', statusCode: 403 };

describe.each(adapters.map((a) => a.name))('authorization e2e (%s)', (adapter) => {
  let app: INestApplication;
  const as = (user?: string) => {
    const agent = request(app.getHttpServer());
    const withUser = <T extends { set(k: string, v: string): T }>(r: T) =>
      user ? r.set('x-user', user) : r;
    return {
      get: (url: string) => withUser(agent.get(url)),
      post: (url: string) => withUser(agent.post(url)),
      patch: (url: string) => withUser(agent.patch(url)),
      delete: (url: string) => withUser(agent.delete(url)),
    };
  };

  beforeAll(async () => {
    app = await createApp(adapter, AppModule);
  });
  afterAll(() => app.close());

  describe('route-level @Can', () => {
    it('allows a user whose ability passes', async () => {
      await as('alice').post('/posts').expect(201, { created: true });
    });

    it('denies with 403 when the ability fails', async () => {
      await as('eve').post('/posts').expect(403, FORBIDDEN);
    });

    it('runs the policy with a null user when there is none', async () => {
      await as().get('/posts').expect(200);
    });

    it('maps a denial without a user to 401', async () => {
      await as().post('/posts').expect(401, UNAUTHORIZED);
    });
  });

  describe('class + method @Can', () => {
    it('passes when both requirements pass', async () => {
      await as('erin').get('/stats/export').expect(200);
    });

    it('fails when only the method-level requirement passes', async () => {
      await as('xavier').get('/stats/export').expect(403);
    });

    it('fails when only the class-level requirement passes', async () => {
      await as('eve').get('/stats').expect(200);
      await as('eve').get('/stats/export').expect(403);
    });
  });

  describe('record-level in a service', () => {
    it('lets the owner update their post', async () => {
      const res = await as('alice').patch('/posts/1').send({ title: 'Renamed' }).expect(200);
      expect(res.body.title).toBe('Renamed');
    });

    it('turns an AuthorizationError into the same 403 as @Can()', async () => {
      await as('bob').patch('/posts/1').send({ title: 'Hijacked' }).expect(403, FORBIDDEN);
    });

    it('passes null to abilities where guests are meaningful', async () => {
      await as().get('/posts/1').expect(200); // published
      await as().get('/posts/2').expect(401, UNAUTHORIZED); // draft, no user
      await as('alice').get('/posts/2').expect(403, FORBIDDEN); // draft, not the author
      await as('bob').get('/posts/2').expect(200); // draft, the author
    });
  });

  describe('before() hook', () => {
    it('lets an admin bypass a policy that always denies', async () => {
      await as('alice').delete('/posts/1').expect(403);
      await as('root').delete('/posts/1').expect(200, { deleted: 1 });
    });

    it('lets an admin bypass record-level abilities that accept guests', async () => {
      await as('root').get('/posts/2').expect(200);
    });

    it('lets an admin bypass route-level abilities too', async () => {
      await as('root').get('/stats/export').expect(200);
    });
  });

  describe('async policy with an injected dependency', () => {
    it('allows a user who is not banned', async () => {
      await as('alice').post('/comments').expect(201);
    });

    it('denies a banned user', async () => {
      await as('mallory').post('/comments').expect(403);
    });
  });

  describe('denial events', () => {
    const events: AuthorizationDeniedEvent[] = [];
    beforeAll(() => app.get(AuthorizationEvents).events$.subscribe((event) => events.push(event)));
    beforeEach(() => (events.length = 0));

    it('report @Can() denials, which the response does not name', async () => {
      await as('eve').post('/posts').expect(403);
      await as().post('/posts').expect(401);

      expect(events).toEqual([
        {
          type: 'denied',
          policy: 'PostPolicy',
          ability: 'create',
          reason: 'forbidden',
          user: users.eve,
          args: [],
          handler: 'PostsController.create',
        },
        {
          type: 'denied',
          policy: 'PostPolicy',
          ability: 'create',
          reason: 'unauthenticated',
          user: null,
          args: [],
          handler: 'PostsController.create',
        },
      ]);
    });

    it('report authorize() denials with the record', async () => {
      await as('alice').get('/posts/2').expect(403);
      expect(events).toEqual([
        {
          type: 'denied',
          policy: 'PostPolicy',
          ability: 'view',
          reason: 'forbidden',
          user: users.alice,
          args: [expect.objectContaining({ id: 2 })],
        },
      ]);
    });
  });
});

describe.each(adapters.map((a) => a.name))('misconfigured @Can() (%s)', (adapter) => {
  it('fails at startup, naming the handler and the fix', async () => {
    await expect(createApp(adapter, MisconfiguredAppModule)).rejects.toThrow(
      "@Can(DraftPolicy, 'view') on DraftsController.list: DraftPolicy is not registered. " +
        'Add it to the providers of a module, or to AuthorizationModule.forRoot({ policies }).',
    );
  });
});
