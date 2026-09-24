import { Injectable, type OnApplicationShutdown } from '@nestjs/common';
import { Subject, type Observable } from 'rxjs';
import type { AuthorizationEvent } from './authorization-events.interface.js';
import { deniedChannel } from './authorization.channels.js';

/**
 * The app's denials, for an audit log or metrics. Each event is also
 * published on the `nestjs:authorization:denied` diagnostics channel, for
 * tooling that runs outside Nest.
 */
@Injectable()
export class AuthorizationEvents implements OnApplicationShutdown {
  private readonly subject = new Subject<AuthorizationEvent>();
  /** Every denial of this application, in order. */
  readonly events$: Observable<AuthorizationEvent> = this.subject.asObservable();

  /** @internal Called by the guard and `AuthorizationService`. */
  emit(event: AuthorizationEvent): void {
    if (deniedChannel.hasSubscribers) {
      deniedChannel.publish(event);
    }
    this.subject.next(event);
  }

  onApplicationShutdown() {
    this.subject.complete();
  }
}
