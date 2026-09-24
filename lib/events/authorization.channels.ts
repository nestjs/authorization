import { channel } from 'node:diagnostics_channel';

/** Every denial, for tooling that runs outside Nest. */
export const deniedChannel = channel('nestjs:authorization:denied');
