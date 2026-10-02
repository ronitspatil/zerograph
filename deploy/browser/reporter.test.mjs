import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { report } from './reporter.mjs';

test('report excludes captured browser and credential diagnostics', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'zerograph-browser-qualification-reporter-'));
  try {
    const file = join(directory, 'result.json');
    assert.equal(await report([{ label: 'case', stage: 'fixed stage', passed: false,
      error: new Error('secret-token'), url: '?code=secret-code', password: 'secret-password' }], file), false);
    const output = await readFile(file, 'utf8');
    assert.ok(!output.includes('secret'));
    assert.deepEqual(JSON.parse(output), { passed: 0, failed: 1,
      cases: [{ label: 'case', passed: false, stage: 'fixed stage' }] });
  } finally {
    await rm(directory, { recursive: true });
  }
});
