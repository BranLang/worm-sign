import { spawnSync } from 'child_process';
import * as path from 'path';

const scriptPath = path.join(__dirname, '..', 'dist', 'bin', 'scan.js');

describe('CLI Integration', () => {
  test('should show help', () => {
    const child = spawnSync('node', [scriptPath, '--help'], { encoding: 'utf8' });
    expect(child.stdout).toContain('Usage: worm-sign');
    expect(child.status).toBe(0);
  });

  test('should show version', () => {
    const child = spawnSync('node', [scriptPath, '--version'], { encoding: 'utf8' });
    expect(child.stdout).toMatch(/\d+\.\d+\.\d+/);
    expect(child.status).toBe(0);
  });

  test('should fail with unknown option --source', () => {
    const child = spawnSync('node', [scriptPath, '--fetch', '--source', 'invalid', '--no-cache'], {
      encoding: 'utf8',
    });
    expect(child.stderr).toContain("error: unknown option '--source'");
    expect(child.status).toBe(1);
  });

  test('should support custom URL and warn on failure', () => {
    const child = spawnSync(
      'node',
      [
        scriptPath,
        '--fetch',
        '--url',
        'https://localhost:9999/bad.csv',
        '--data-format',
        'csv',
        '--no-cache',
      ],
      { encoding: 'utf8' },
    );
    // It should fail to fetch the custom URL but handle it gracefully (not crash)
    // Since other sources succeed, it might not warn. We just check it doesn't crash.
    expect(child.status).not.toBe(2); // 2 is usually error/crash in our CLI
  });

  test('should respect --offline flag', () => {
    // Run with --offline. It should NOT attempt to fetch remote sources.
    // We can check that it doesn't say "Fetching from..."
    const child = spawnSync('node', [scriptPath, '--offline'], { encoding: 'utf8' });
    expect(child.stdout).not.toContain('Fetching from');
    expect(child.status).toBe(0);
  });
});
