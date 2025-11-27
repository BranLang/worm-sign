import { spawnSync } from 'child_process';
import * as path from 'path';

const scriptPath = path.join(__dirname, '..', 'dist', 'bin', 'scan.js');

describe('Visual Output Snapshots', () => {
  test('should match snapshot for help command', () => {
    const child = spawnSync('node', [scriptPath, '--help'], { encoding: 'utf8', env: { ...process.env, FORCE_COLOR: '1' } });
    expect(child.stdout).toMatchSnapshot();
  });

  test('should match snapshot for version command', () => {
    const child = spawnSync('node', [scriptPath, '--version'], { encoding: 'utf8', env: { ...process.env, FORCE_COLOR: '1' } });
    expect(child.stdout).toMatchSnapshot();
  });
});
