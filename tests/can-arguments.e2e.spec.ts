/**
 * `@Can()` with arguments read from the call: a scope check on a route
 * param, declared on the route instead of an `authorize()` call in the
 * handler that a later edit could drop.
 */
import { ApolloDriver, type ApolloDriverConfig } from '@nestjs/apollo';
import {
  Controller,
  Get,
  Injectable,
  Module,
  Param,
  ParseIntPipe,
  type CanActivate,
  type ExecutionContext,
  type INestApplication,
} from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { Args, GqlExecutionContext, GraphQLModule, Query, Resolver } from '@nestjs/graphql';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import { AuthorizationEvents, AuthorizationModule, Can, Policy, type AuthorizationEvent } from '../lib/index.js';
import { users, type User } from './fixtures.js';

/** Which workouts each user may see: a rights tree resolved from ids, without loading a workout. */
const sharedWith: Record<number, string[]> = { [users.alice.id]: ['1', '2'], [users.bob.id]: ['3'] };

@Policy()
class WorkoutPolicy {
  view(user: User | null, workoutId: string) {
    return !!user && (sharedWith[user.id] ?? []).includes(workoutId);
  }
}

@Injectable()
class HeaderAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const req =
      context.getType<string>() === 'graphql' ? context.getArgByIndex(2).req : context.switchToHttp().getRequest();
    req.user = users[req.headers['x-user']];
    return true;
  }
}

@Controller('workouts')
class WorkoutsController {
  @Get(':workoutId')
  // Before pipes: the policy gets the param as the string the URL carried.
  @Can(WorkoutPolicy, 'view', (context) => [context.switchToHttp().getRequest().params.workoutId])
  findOne(@Param('workoutId', ParseIntPipe) id: number) {
    return { id };
  }
}

@Resolver()
class WorkoutsResolver {
  @Query('workout')
  @Can(WorkoutPolicy, 'view', (context) => [GqlExecutionContext.create(context).getArgs<{ id: string }>().id])
  workout(@Args('id') id: string) {
    return id;
  }
}

@Module({
  imports: [AuthorizationModule.forRoot({ policies: [WorkoutPolicy] })],
  controllers: [WorkoutsController],
  providers: [{ provide: APP_GUARD, useClass: HeaderAuthGuard }],
})
class HttpAppModule {}

describe.each(adapters.map((a) => a.name))('@Can() with a route param (%s)', (adapter) => {
  let app: INestApplication;
  const events: AuthorizationEvent[] = [];

  beforeAll(async () => {
    app = await createApp(adapter, HttpAppModule);
    app.get(AuthorizationEvents).events$.subscribe((event) => events.push(event));
  });
  afterAll(() => app.close());
  beforeEach(() => {
    events.length = 0;
  });

  it('checks the workout in the URL before the handler runs', async () => {
    await request(app.getHttpServer()).get('/workouts/1').set('x-user', 'alice').expect(200, { id: 1 });
    await request(app.getHttpServer()).get('/workouts/3').set('x-user', 'alice').expect(403);
    await request(app.getHttpServer()).get('/workouts/3').set('x-user', 'bob').expect(200, { id: 3 });
    await request(app.getHttpServer()).get('/workouts/1').expect(401);
  });

  it('reports the param with the denial', async () => {
    await request(app.getHttpServer()).get('/workouts/3').set('x-user', 'alice').expect(403);
    expect(events).toEqual([
      {
        type: 'denied',
        policy: 'WorkoutPolicy',
        ability: 'view',
        reason: 'forbidden',
        user: users.alice,
        args: ['3'],
        handler: 'WorkoutsController.findOne',
      },
    ]);
  });

  it('denies before the pipes run: an id the user may not see is a 403, not a 400', async () => {
    await request(app.getHttpServer()).get('/workouts/abc').set('x-user', 'alice').expect(403);
  });
});

describe('@Can() with a GraphQL argument', () => {
  @Module({
    imports: [
      GraphQLModule.forRoot<ApolloDriverConfig>({
        driver: ApolloDriver,
        typeDefs: 'type Query { workout(id: ID!): ID }',
        context: ({ req }: { req: unknown }) => ({ req }),
      }),
      AuthorizationModule.forRoot({ policies: [WorkoutPolicy] }),
    ],
    providers: [{ provide: APP_GUARD, useClass: HeaderAuthGuard }, WorkoutsResolver],
  })
  class GqlAppModule {}

  let app: INestApplication;
  const workout = (id: string, user: string) =>
    request(app.getHttpServer())
      .post('/graphql')
      .set('x-user', user)
      .send({ query: `{ workout(id: "${id}") }` })
      .expect(200);

  beforeAll(async () => {
    app = await createApp('express', GqlAppModule);
  });
  afterAll(() => app.close());

  it("reads the operation's arguments through GqlExecutionContext", async () => {
    expect((await workout('2', 'alice')).body.data).toEqual({ workout: '2' });
    expect((await workout('3', 'alice')).body.errors[0]).toMatchObject({
      message: 'Forbidden',
      extensions: { code: 'FORBIDDEN' },
    });
  });
});
