import { execSync } from 'child_process';
import * as path from 'path';

const scanBin = path.resolve(__dirname, '../dist/bin/scan.js');

function runCommand(args: string) {
  try {
    console.log(`Running: node ${scanBin} ${args}`);
    const out = execSync(`node ${scanBin} ${args} 2>&1`, { encoding: 'utf8', stdio: 'pipe' });
    // Strip ANSI codes (more robust regex)
    // eslint-disable-next-line no-control-regex
    return out.replace(/\u001b\[[0-9;]*m/g, '');
  } catch (error: any) {
    // If the command fails (exit code != 0), return the stdout/stderr so we can inspect it
    // Some commands might fail if they find vulnerabilities, but in this repo they shouldn't.
    // If they do fail, we want to know why.
    throw new Error(
      `Command failed: node ${scanBin} ${args}\nOutput: ${error.stdout}\nError: ${error.stderr}`,
    );
  }
}

describe('README Commands Audit', () => {
  // 1. Basic Scan
  test('worm-sign (Basic Scan)', () => {
    const output = runCommand('');
    expect(output).toContain('WORM SIGN');
    expect(output).toContain('No wormsign detected');
  });

  // 2. Fetch Latest Data
  test('worm-sign --fetch', () => {
    const output = runCommand('--fetch');
    expect(output).toContain('Fetched');
    expect(output).toContain('No wormsign detected');
  }, 30000); // Increase timeout for network

  // 3. Custom Data Source (JSON)
  test('worm-sign --url ... --data-format json', () => {
    // We use a dummy URL that will fail, but thanks to graceful handling, it should warn and pass
    // or we can use a real one if we have a stable one.
    // Let's use a non-existent one to test graceful failure which is also documented.
    const output = runCommand(
      '--url "https://this-domain-does-not-exist.test/vulns.json" --data-format json',
    );
    expect(output).toContain('Failed to fetch'); // Should warn about fetch failure
    expect(output).toContain('No wormsign detected'); // But still succeed with local sources
  });

  // 4. Custom Data Source (CSV)
  test('worm-sign --url ... --data-format csv', () => {
    const output = runCommand(
      '--url "https://this-domain-does-not-exist.test/vulns.csv" --data-format csv',
    );
    expect(output).toContain('Failed to fetch');
    expect(output).toContain('No wormsign detected');
  });

  // 5. Output Formats (SARIF)
  test('worm-sign --format sarif', () => {
    const output = runCommand('--format sarif');
    // Should be valid JSON
    const sarif = JSON.parse(output);
    expect(sarif.runs[0].tool.driver.name).toBe('worm-sign');
  });

  // 6. Caching
  test('worm-sign --fetch --no-cache', () => {
    const output = runCommand('--fetch --no-cache');
    expect(output).toContain('Fetched');
  }, 30000);

  // 7. Enterprise Usage (Offline)
  test('npx worm-sign --offline', () => {
    const output = runCommand('--offline');
    // Should NOT fetch
    expect(output).not.toContain('Fetching from');
    expect(output).toContain('No wormsign detected');
  });

  // 8. Enterprise Usage (Offline + Custom URL)
  test('npx worm-sign --offline --url ...', () => {
    // This is the "Internal Mirror" use case.
    // Since we are offline, it should ONLY try to fetch from the custom URL (if implemented that way)
    const output = runCommand(
      '--offline --url "https://this-domain-does-not-exist.test/mirror.csv" --data-format csv',
    );

    // It SHOULD attempt to fetch (and fail because of the dummy URL)
    expect(output).toContain('Fetching');
    expect(output).toContain('Failed to fetch');
    expect(output).toContain('No wormsign detected');
  });
});
