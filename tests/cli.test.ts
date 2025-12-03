import { spawnSync } from 'child_process';
import * as path from 'path';

const scriptPath = path.join(__dirname, '..', 'bin', 'scan.ts');

function runCli(args: string[]) {
  return spawnSync('node', ['-r', 'ts-node/register', scriptPath, ...args], {
    encoding: 'utf8',
    shell: true,
    env: { ...process.env, TS_NODE_TRANSPILE_ONLY: 'true' }, // Speed up
  });
}

describe('CLI Integration', () => {
  test('should show help', () => {
    const child = runCli(['--help']);
    expect(child.stdout).toContain('Usage: worm-sign');
    expect(child.status).toBe(0);
  });

  test('should show version', () => {
    const child = runCli(['--version']);
    expect(child.stdout).toMatch(/\d+\.\d+\.\d+/);
    expect(child.status).toBe(0);
  });

  test('should support custom URL and warn on failure', () => {
    const child = runCli([
      '--fetch',
      '--url',
      'https://localhost:9999/bad.csv',
      '--data-format',
      'csv',
      '--no-cache',
    ]);
    // It should fail to fetch the custom URL but handle it gracefully (not crash)
    expect(child.status).not.toBe(2);
  });

  test('should respect --offline flag', () => {
    // Run with --offline. It should NOT attempt to fetch remote sources.
    // Use --dry-run to ensure exit code 0 even if local vulns are found
    const child = runCli(['--offline', '--dry-run']);
    if (child.status !== 0) {
      console.log('OFFLINE TEST FAILED');
      console.log('STDOUT:', child.stdout);
      console.log('STDERR:', child.stderr);
    }
    expect(child.stdout).not.toContain('Fetching from');
    expect(child.status).toBe(0);
  });
});
