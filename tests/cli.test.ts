import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
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

  test('exits 1 on critical heuristic finding even without compromised-package match', () => {
    // Manifest-only TanStack-style malicious optionalDependencies pin.
    // No package in known-threats.csv matches by name@version, but the
    // manifest heuristic should fail the build on its own.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wormsign-cli-crit-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({
          name: 'victim',
          version: '1.0.0',
          optionalDependencies: {
            '@tanstack/setup':
              'github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c',
          },
        }),
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({ name: 'victim', version: '1.0.0', lockfileVersion: 3, packages: {} }),
      );

      const child = runCli(['--offline', '--path', tmp]);
      expect(child.stdout + child.stderr).toMatch(/malicious-git-ref|Malicious git ref|TanStack wave 4|CRITICAL/i);
      expect(child.status).toBe(1);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }, 30000);

  test('dry-run still exits 0 even with critical heuristic finding', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wormsign-cli-dry-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({
          name: 'victim',
          version: '1.0.0',
          optionalDependencies: {
            '@tanstack/setup':
              'github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c',
          },
        }),
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({ name: 'victim', version: '1.0.0', lockfileVersion: 3, packages: {} }),
      );
      const child = runCli(['--offline', '--dry-run', '--path', tmp]);
      expect(child.status).toBe(0);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }, 30000);
});
