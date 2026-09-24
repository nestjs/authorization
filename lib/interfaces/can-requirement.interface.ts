import type { Type } from '@nestjs/common';

/** One `@Can()` requirement, as stored in the handler or class metadata. */
export interface CanRequirement {
  policy: Type<unknown>;
  ability: string;
}
