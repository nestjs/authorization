import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Injectable,
  Module,
  NotFoundException,
  Param,
  ParseIntPipe,
  Patch,
  Post as HttpPost,
  Req,
  type CanActivate,
  UnauthorizedException,
  type ExecutionContext,
} from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import {
  AuthorizationModule,
  AuthorizationService,
  Can,
  Policy,
  type PolicyBefore,
} from '../lib/index.js';

// ---- Domain -------------------------------------------------------------
// Plain object types, the shape Prisma/Drizzle/Kysely rows have. No classes.

export type User = { id: number; roles: string[] };
export type Post = { id: number; authorId: number; title: string; published: boolean };

export const users: Record<string, User> = {
  alice: { id: 1, roles: ['writer'] },
  bob: { id: 2, roles: ['writer'] },
  root: { id: 99, roles: ['admin'] },
  eve: { id: 3, roles: ['editor'] },
  xavier: { id: 4, roles: ['exporter'] },
  erin: { id: 5, roles: ['editor', 'exporter'] },
  mallory: { id: 666, roles: ['writer'] },
};

// ---- Policies -----------------------------------------------------------

@Policy()
export class PostPolicy implements PolicyBefore<User> {
  before(user: User | null) {
    if (user?.roles.includes('admin')) {
      return true;
    }
    return undefined;
  }

  // Route-level abilities take `User | null`: the guard may run without a user.
  viewAny(_user: User | null) {
    return true;
  }

  create(user: User | null) {
    return !!user?.roles.includes('writer');
  }

  viewStats(user: User | null) {
    return !!user?.roles.includes('editor');
  }

  exportStats(user: User | null) {
    return !!user?.roles.includes('exporter');
  }

  // Record-level abilities called from services can require a User: the
  // compiler makes the caller narrow first.
  update(user: User, post: Post) {
    return post.authorId === user.id;
  }

  delete(_user: User, _post: Post) {
    return false; // admins only, via before()
  }

  // Guests may read published posts; authors may read their drafts.
  view(user: User | null, post: Post) {
    return post.published || post.authorId === user?.id;
  }

  /** Not an ability: does not return boolean. */
  describe(post: Post) {
    return `post #${post.id}`;
  }
}

@Injectable()
export class BanList {
  async isBanned(userId: number): Promise<boolean> {
    await new Promise((r) => setTimeout(r, 5));
    return userId === 666;
  }
}

@Policy()
export class CommentPolicy {
  constructor(private readonly banList: BanList) {}

  async create(user: User | null): Promise<boolean> {
    return !!user && !(await this.banList.isBanned(user.id));
  }
}

/** Decorated but deliberately never registered. */
@Policy()
export class DraftPolicy {
  view(_user: User | null) {
    return true;
  }
}

// ---- Authentication stand-in -------------------------------------------

/** Global guard that sets `request.user` from the `x-user` header. */
@Injectable()
export class HeaderAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    const name = request.headers['x-user'];
    if (typeof name === 'string' && users[name]) {
      request.user = users[name];
    }
    return true;
  }
}

function requireUser(req: { user?: User }): User {
  if (!req.user) {
    throw new UnauthorizedException();
  }
  return req.user;
}

// ---- Application --------------------------------------------------------

@Injectable()
export class PostsService {
  private posts = new Map<number, Post>([
    [1, { id: 1, authorId: 1, title: 'Alice writes', published: true }],
    [2, { id: 2, authorId: 2, title: 'Bob drafts', published: false }],
  ]);

  constructor(private readonly authorization: AuthorizationService) {}

  find(id: number) {
    const post = this.posts.get(id);
    if (!post) {
      throw new NotFoundException();
    }
    return post;
  }

  /** Guests are meaningful here: the user may be null. */
  async show(user: User | null, id: number) {
    const post = this.find(id);
    await this.authorization.authorize(PostPolicy, 'view', user, post);
    return post;
  }

  async rename(user: User, id: number, title: string) {
    const post = this.find(id);
    await this.authorization.authorize(PostPolicy, 'update', user, post);
    post.title = title;
    return post;
  }

  async remove(user: User, id: number) {
    const post = this.find(id);
    await this.authorization.authorize(PostPolicy, 'delete', user, post);
    return { deleted: id };
  }
}

@Controller('posts')
@Can(PostPolicy, 'viewAny')
export class PostsController {
  constructor(private readonly posts: PostsService) {}

  @Get()
  list() {
    return [{ id: 1 }, { id: 2 }];
  }

  @HttpPost()
  @Can(PostPolicy, 'create')
  create() {
    return { created: true };
  }

  @Get(':id')
  show(@Req() req: any, @Param('id', ParseIntPipe) id: number) {
    return this.posts.show(req.user, id);
  }

  // `update` and `delete` require a User, so these routes need one. In a real
  // app authentication guarantees that; this stand-in does not, so check here.
  @Patch(':id')
  rename(@Req() req: any, @Param('id', ParseIntPipe) id: number, @Body() body: { title: string }) {
    return this.posts.rename(requireUser(req), id, body.title);
  }

  @Delete(':id')
  @HttpCode(200)
  remove(@Req() req: any, @Param('id', ParseIntPipe) id: number) {
    return this.posts.remove(requireUser(req), id);
  }
}

@Controller('stats')
@Can(PostPolicy, 'viewStats')
export class StatsController {
  @Get()
  view() {
    return { views: 42 };
  }

  @Get('export')
  @Can(PostPolicy, 'exportStats')
  export() {
    return { csv: 'views\n42' };
  }
}

@Controller('comments')
export class CommentsController {
  @HttpPost()
  @Can(CommentPolicy, 'create')
  create() {
    return { created: true };
  }
}

/** Policy lives in the feature module so it can inject BanList. */
@Module({
  controllers: [CommentsController],
  providers: [BanList, CommentPolicy],
})
export class CommentsModule {}

@Module({
  imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] }), CommentsModule],
  controllers: [PostsController, StatsController],
  providers: [{ provide: APP_GUARD, useClass: HeaderAuthGuard }, PostsService],
})
export class AppModule {}

// ---- Misconfigured app (missing policy) ---------------------------------

@Controller('drafts')
export class DraftsController {
  @Get()
  @Can(DraftPolicy, 'view')
  list() {
    return [];
  }
}

@Module({
  imports: [AuthorizationModule.forRoot({ policies: [PostPolicy] })],
  controllers: [DraftsController],
  providers: [{ provide: APP_GUARD, useClass: HeaderAuthGuard }],
})
export class MisconfiguredAppModule {}
