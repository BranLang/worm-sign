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

  test('should fail with unknown source', () => {
    const child = spawnSync('node', [scriptPath, '--fetch', '--source', 'invalid', '--no-cache'], { encoding: 'utf8' });
    expect(child.stderr).toContain('Unknown source');
    expect(child.status).toBe(2);
  });

  test('should support custom URL', () => {
    // We can't easily mock the network for a spawned process without a local server.
    // But we can check if it attempts to fetch.
    // Or we can use the --no-cache flag and expect a failure if the URL is unreachable, 
    // but formatted correctly.
    const child = spawnSync('node', [scriptPath, '--fetch', '--url', 'https://localhost:9999/bad.csv', '--data-format', 'csv', '--no-cache'], { encoding: 'utf8' });
    // It should fail to fetch but handle it gracefully by falling back or showing error
    expect(child.stderr).toContain('Failed to fetch');
  });
});
