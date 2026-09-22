import test from 'node:test';
import assert from 'node:assert/strict';
import { resumableReplacement } from '../src/databaseReplacement.ts';

const scope = { tenant: 'tenant-one', site: 'site-one', database: 'db-one', generation: 2 };
const state = () => ({ status: 'completed', job: { id: 'import-one', direction: 'import', conflict_policy: 'replace', tenant_id: scope.tenant, site_id: scope.site, database_id: scope.database, database_generation: 1, digest: 'a'.repeat(64), restore_point_ref: 'import-one', restore_point_digest: 'b'.repeat(64) } });

test('resumes only the exact completed replacement at its current target generation', () => {
  const current = state();
  assert.equal(resumableReplacement(current, 'import-one', scope), current.job);
});

test('rejects wrong tenant, site, target, requested job, and stale generations', () => {
  for (const [field, value] of Object.entries({ tenant_id: 'other', site_id: 'other', database_id: 'other', id: 'other', database_generation: 2 })) {
    const wrong = state(); wrong.job[field] = value;
    assert.throws(() => resumableReplacement(wrong, 'import-one', scope));
  }
  assert.throws(() => resumableReplacement(state(), 'import-one', { ...scope, generation: 3 }));
});

test('rejects active, ambiguous, nonreplacement, or incomplete recovery evidence', () => {
  for (const status of ['queued', 'promoting', 'ambiguous', 'failed', 'cancelled']) {
    assert.throws(() => resumableReplacement({ ...state(), status }, 'import-one', scope));
  }
  for (const [field, value] of Object.entries({ direction: 'export', conflict_policy: 'fail', restore_point_ref: '', restore_point_digest: '', digest: '' })) {
    const wrong = state(); wrong.job[field] = value;
    assert.throws(() => resumableReplacement(wrong, 'import-one', scope));
  }
  for (const invalid of [null, [], {}, { status: 'completed', job: null }]) assert.throws(() => resumableReplacement(invalid, 'import-one', scope));
});
