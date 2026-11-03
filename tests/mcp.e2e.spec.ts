/**
 * Calls of an MCP server's tools (`@nestjs/mcp`), on Express and Fastify: `@Can()` on each call, with the user that
 * authentication left on the HTTP request the call arrived in, `args` read from the call's input, `authorize()` in a
 * service, the default denial of a tool that declares nothing, and stdio, where the call's context carries the user.
 * `@nestjs/mcp` is not a dependency: a stand-in endpoint calls tools the way it does, through Nest's
 * `ExternalContextCreator` with the context type `mcp` and the arguments `[input, context]`.
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

/** The second argument of a call: `@nestjs/mcp`'s `McpContext`, as far as this package reads it. */
interface McpCall {
  kind: 'tool';
  name: string;
  transport: 'http' | 'stdio';
  request?: { headers: Record<string, string | undefined>; user?: User };
  user?: User;
}

type ToolResult = { result: unknown } | { isError: true; status: number; message: string };

/** Calls tools as `@nestjs/mcp` does, and answers an `HttpException` with a tool error carrying its message. */
@Injectable()
class McpStandIn {
  private readonly tools = new Map<string, (input: unknown, call: McpCall) => Promise<unknown>>();

  constructor(private readonly contexts: ExternalContextCreator) {}

  register(instance: object, methodName: string) {
    const method = Object.getPrototypeOf(instance)[methodName];
    this.tools.set(
      methodName,
      this.contexts.create(instance, method, methodName, undefined, undefined, undefined, undefined, undefined, 'mcp'),
    );
  }

  async call(name: string, input: unknown, call: McpCall): Promise<ToolResult> {
    try {
      return { result: await this.tools.get(name)!(input, call) };
    } catch (error) {
      if (!(error instanceof HttpException)) {
        throw error;
      }
      return { isError: true, status: error.getStatus(), message: error.message };
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
class NoteTools implements OnModuleInit {
  constructor(
    private readonly mcp: McpStandIn,
    private readonly notes: NotesService,
  ) {}

  onModuleInit() {
    for (const name of ['create', 'edit', 'archive', 'forgotten']) {
      this.mcp.register(this, name);
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
  archive(_input: unknown, call: McpCall) {
    return this.notes.archive(call.request?.user ?? call.user ?? null);
  }

  forgotten() {
    return 'leaked';
  }
}

/**
 * What an authentication guard does, as `@nestjs/authentication`'s does: the user of `x-user` on the HTTP request,
 * which the MCP calls of that request read; over stdio, where there is none, on the call's own context.
 */
@Injectable()
class HeaderAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    if (context.getType<string>() === 'http') {
      const req = context.switchToHttp().getRequest();
      req.user = users[req.headers['x-user']];
    }
    if (context.getType<string>() === 'mcp') {
      const call = context.getArgByIndex(1) as McpCall;
      if (!call.request) {
        call.user = users[process.env.MCP_LOCAL_USER ?? ''];
      }
    }
    return true;
  }
}

/** The MCP endpoint, as `@nestjs/mcp` adds it: a route, open to anyone (each call is checked on its own). */
@Controller('mcp')
@Can.Anyone()
class McpController {
  constructor(private readonly mcp: McpStandIn) {}

  @Post()
  @HttpCode(200)
  call(@Req() req: McpCall['request'], @Body() body: { name: string; arguments?: object }) {
    return this.mcp.call(body.name, body.arguments ?? {}, { kind: 'tool', name: body.name, transport: 'http', request: req });
  }
}

@Module({
  imports: [AuthorizationModule.forRoot({ policies: [NotePolicy] })],
  controllers: [McpController],
  providers: [McpStandIn, NotesService, NoteTools, { provide: APP_GUARD, useClass: HeaderAuthGuard }],
})
class McpAppModule {}

describe.each(adapters.map((adapter) => adapter.name))('MCP tool calls over HTTP (%s)', (adapter) => {
  let app: INestApplication;
  const callTool = (name: string, user?: string, args: object = {}) => {
    const req = request(app.getHttpServer()).post('/mcp');
    if (user) {
      req.set('x-user', user);
    }
    return req.send({ name, arguments: args }).expect(200);
  };

  beforeAll(async () => {
    app = await createApp(adapter, McpAppModule);
  });
  afterAll(() => app.close());

  it('lets a call through when the policy allows it, for the user on the request the call arrived in', async () => {
    expect((await callTool('create', 'alice')).body).toEqual({ result: 'created' });
  });

  it('refuses a call the policy denies with a ForbiddenException, which @nestjs/mcp answers with a tool error', async () => {
    expect((await callTool('create', 'eve')).body).toEqual({ isError: true, status: 403, message: 'Forbidden' });
  });

  it('refuses a guest with an UnauthorizedException', async () => {
    expect((await callTool('create')).body).toEqual({ isError: true, status: 401, message: 'Unauthorized' });
  });

  it("reads the ability's arguments from the call's input", async () => {
    expect((await callTool('edit', 'alice', { noteId: 10 })).body).toEqual({ result: 'edited 10' });
    expect((await callTool('edit', 'alice', { noteId: 20 })).body).toMatchObject({ isError: true, status: 403 });
  });

  it('answers a denial from authorize() in a service the same way', async () => {
    expect((await callTool('archive', 'root')).body).toEqual({ result: 'archived' });
    expect((await callTool('archive', 'alice')).body).toEqual({ isError: true, status: 403, message: 'Forbidden' });
  });

  it('denies a tool that declares no @Can(), as it does a route', async () => {
    expect((await callTool('forgotten', 'root')).body).toMatchObject({ isError: true, status: 403 });
  });
});

describe('MCP tool calls over stdio', () => {
  it("reads the user from the call's own context, where there is no request", async () => {
    vi.stubEnv('MCP_LOCAL_USER', 'alice');
    const moduleRef = await Test.createTestingModule({ imports: [McpAppModule] }).compile();
    await moduleRef.init();
    try {
      const mcp = moduleRef.get(McpStandIn);
      const stdio = (name: string): McpCall => ({ kind: 'tool', name, transport: 'stdio' });
      expect(await mcp.call('create', {}, stdio('create'))).toEqual({ result: 'created' });
      expect(await mcp.call('edit', { noteId: 20 }, stdio('edit'))).toMatchObject({ isError: true, status: 403 });

      vi.stubEnv('MCP_LOCAL_USER', '');
      expect(await mcp.call('create', {}, stdio('create'))).toMatchObject({ isError: true, status: 401 });
    } finally {
      vi.unstubAllEnvs();
      await moduleRef.close();
    }
  });
});
