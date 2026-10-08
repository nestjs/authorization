import type { ExecutionContext, Type } from '@nestjs/common';

/** One `@Can()` requirement, as stored in the handler or class metadata. */
export interface CanRequirement {
  policy: Type<unknown>;
  ability: string;
  /** Reads the ability's arguments after the user from the call; none when absent. */
  args?: (context: ExecutionContext) => readonly unknown[] | Promise<readonly unknown[]>;
}
