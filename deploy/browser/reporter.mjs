import { writeFile } from 'node:fs/promises';

// Never persist browser errors, call logs, page contents, URLs or credentials.
export async function report(outcomes, destination) {
  const result = {
    passed: outcomes.filter(item => item.passed).length,
    failed: outcomes.filter(item => !item.passed).length,
    cases: outcomes.map(({ label, passed, stage }) => ({ label, passed, stage })),
  };
  await writeFile(destination, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  return result.failed === 0;
}
