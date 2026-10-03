import { writeFile } from 'node:fs/promises';

// Never persist browser errors, call logs, page contents, URLs or credentials.
export async function report(outcomes, destination) {
  const result = {
    passed: outcomes.filter(item => item.passed).length,
    failed: outcomes.filter(item => !item.passed).length,
    cases: outcomes.map(({ label, passed, stage, diagnostics }) => ({ label, passed, stage,
      ...(diagnostics ? { diagnostics: Object.fromEntries([
        'page_errors', 'console_errors', 'csp_errors', 'api_success', 'api_denied', 'api_server_errors',
        'document_nonce_present', 'script_count', 'script_nonce_match', 'script_nonce_mismatch',
        'favicon_errors', 'resource_errors',
      ].map(key => [key, Number.isSafeInteger(diagnostics[key]) ? diagnostics[key] : 0])) } : {}),
    })),
  };
  await writeFile(destination, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  return result.failed === 0;
}
