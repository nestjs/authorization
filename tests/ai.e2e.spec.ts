/**
 * Calls of agent functions (`@nestjs/ai`), on Express and Fastify: `@Can()` on each call, with the user that
 * authentication left on the HTTP request the agent runs in, `args` read from the call's input, `authorize()` in a
 * service, the default denial of a function that declares nothing, and jobs, where the call's context carries the user
 * the agent acts for. `@nestjs/ai` is not a dependency: a stand-in calls functions the way it does, through Nest's
 * `ExternalContextCreator` with the context type `ai` and the arguments `[input, context]`.
 */
import {
  Body,
  Controller,
  HttpCode,
  HttpException,
  Injectable,
  Module,
  Post,
  Req,
  type CanActivate,
  type ExecutionContext,
  type INestApplication,
  type OnModuleInit,
} from '@nestjs/common';
import { APP_GUARD, ExternalContextCreator } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { adapters, createApp } from './support/adapters.js';
import { AuthorizationModule, AuthorizationService, Can, Policy } from '../lib/index.js';
import { users, type User } from './fixtures.js';

/** The second argument of a call: `@nestjs/ai`'s `AgentFunctionContext`, as far as this package reads it. */
interface AgentCall {
  name: string;
  request?: { headers: Record<string, string | undefined>; user?: User };
  user?: User;
}

type FunctionResult = { output: unknown } | { error: string; status: number };

/** Calls functions as `@nestjs/ai` does, and answers an `HttpException` with the error the model reads. */
@Injectable()
class AgentStandIn {
  private readonly functions = new Map<string, (input: unknown, call: AgentCall) => Promise<unknown>>();

  constructor(private readonly contexts: ExternalContextCreator) {}

  register(instance: object, methodName: string) {
    const method = Object.getPrototypeOf(instance)[methodName];
    this.functions.set(
      methodName,
      this.contexts.create(instance, method, methodName, undefined, undefined, undefined, undefined, undefined, 'ai'),
    );
  }

  async call(name: string, input: unknown, call: AgentCall): Promise<FunctionResult> {
    try {
      return { output: await this.functions.get(name)!(input, call) };
    } catch (error) {
      if (!(error instanceof HttpException)) {
        throw error;
      }
      return { error: error.message, status: error.getStatus() };
    }
  }
}

const owners: Record<number, number> = { 10: users.alice.id, 20: users.bob.id };

@Policy()
class NotePolicy {
  create(user: User | null) {
    return !!user?.roles.includes('writer');
  }

  edit(user: User | null, noteId: number) {
    return user !== null && owners[noteId] === user.id;
  }

  archive(user: User | null) {
    return !!user?.roles.includes('admin');
  }
}

@Injectable()
class NotesService {
  constructor(private readonly authorization: AuthorizationService) {}

  async archive(user: User | null) {
    await this.authorization.authorize(NotePolicy, 'archive', user);
    return 'archived';
  }
}

@Injectable()
class NoteFunctions implements OnModuleInit {
  constructor(
    private readonly agent: AgentStandIn,
    private readonly notes: NotesService,
  ) {}

  onModuleInit() {
    for (const name of ['create', 'edit', 'archive', 'forgotten']) {
      this.agent.register(this, name);
    }
  }

  @Can(NotePolicy, 'create')
  create() {
    return 'created';
  }

  /** The ability's argument comes from the call's input, the first of its arguments. */
  @Can(NotePolicy, 'edit', (context) => [(context.getArgByIndex(0) as { noteId: number }).noteId])
  edit({ noteId }: { noteId: number }) {
    return `edited ${noteId}`;
  }

  @Can.Anyone()
  archive(_input: unknown, call: AgentCall) {
    return this.notes.archive(call.request?.user ?? call.user ?? null);
  }

  forgotten() {
    return 'leaked';
  }
}

/**
 * What an authentication guard does, as `@nestjs/authentication`'s does: the user of `x-user` on the HTTP request,
 * which the agent's calls in that request read. A job's call carries its user on its own context.
 */
@Injectable()
class HeaderAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    if (context.getType<string>() === 'http') {
      const req = context.switchToHttp().getRequest();
      req.user = users[req.headers['x-user']];
    }
    return true;
  }
}

/** A route that runs the agent, open to anyone: each function call is checked on its own. */
@Controller('assistant')
@Can.Anyone()
class AssistantController {
  constructor(private readonly agent: AgentStandIn) {}

  @Post()
  @HttpCode(200)
  call(@Req() req: AgentCall['request'], @Body() body: { name: string; input?: object }) {
    return this.agent.call(body.name, body.input ?? {}, { name: body.name, request: req });
  }
}

@Module({
  imports: [AuthorizationModule.forRoot({ policies: [NotePolicy] })],
  controllers: [AssistantController],
  providers: [AgentStandIn, NotesService, NoteFunctions, { provide: APP_GUARD, useClass: HeaderAuthGuard }],
})
class AgentAppModule {}

describe.each(adapters.map((adapter) => adapter.name))('agent function calls in an HTTP request (%s)', (adapter) => {
  let app: INestApplication;
  const callFunction = (name: string, user?: string, input: object = {}) => {
    const req = request(app.getHttpServer()).post('/assistant');
    if (user) {
      req.set('x-user', user);
    }
    return req.send({ name, input }).expect(200);
  };

  beforeAll(async () => {
    app = await createApp(adapter, AgentAppModule);
  });
  afterAll(() => app.close());

  it('lets a call through when the policy allows it, for the user on the request the agent runs in', async () => {
    expect((await callFunction('create', 'alice')).body).toEqual({ output: 'created' });
  });

  it('refuses a call the policy denies with a ForbiddenException, which @nestjs/ai gives the model', async () => {
    expect((await callFunction('create', 'eve')).body).toEqual({ error: 'Forbidden', status: 403 });
  });

  it('refuses a guest with an UnauthorizedException', async () => {
    expect((await callFunction('create')).body).toEqual({ error: 'Unauthorized', status: 401 });
  });

  it("reads the ability's arguments from the call's input", async () => {
    expect((await callFunction('edit', 'alice', { noteId: 10 })).body).toEqual({ output: 'edited 10' });
    expect((await callFunction('edit', 'alice', { noteId: 20 })).body).toMatchObject({ status: 403 });
  });

  it('answers a denial from authorize() in a service the same way', async () => {
    expect((await callFunction('archive', 'root')).body).toEqual({ output: 'archived' });
    expect((await callFunction('archive', 'alice')).body).toEqual({ error: 'Forbidden', status: 403 });
  });

  it('denies a function that declares no @Can(), as it does a route', async () => {
    expect((await callFunction('forgotten', 'root')).body).toMatchObject({ status: 403 });
  });
});

describe('agent function calls in a job', () => {
  it("reads the user the agent acts for from the call's own context, where there is no request", async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AgentAppModule] }).compile();
    await moduleRef.init();
    try {
      const agent = moduleRef.get(AgentStandIn);
      const job = (name: string, user?: User): AgentCall => ({ name, ...(user && { user }) });
      expect(await agent.call('create', {}, job('create', users.alice))).toEqual({ output: 'created' });
      expect(await agent.call('edit', { noteId: 20 }, job('edit', users.alice))).toMatchObject({ status: 403 });
      expect(await agent.call('create', {}, job('create'))).toMatchObject({ status: 401 });
    } finally {
      await moduleRef.close();
    }
  });
});
