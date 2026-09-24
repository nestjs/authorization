/** A check or a `@Can()` names a policy that is not registered, or not a policy. */
export class MissingPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MissingPolicyError';
  }
}
