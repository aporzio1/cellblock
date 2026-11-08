import { MonitoringCoordinator } from '../index.js';
export { FordRateLimiter } from '../index.js';

// Test-only entry point: the coordinator and its run() are production code.
export class TestCoordinator extends MonitoringCoordinator {
  async seedOwner(owner) { await this.ctx.storage.put('activeOwner', owner); }
  async owner() { return (await this.ctx.storage.get('activeOwner')) ?? null; }
}
export default { fetch() { return new Response('test harness'); } };
