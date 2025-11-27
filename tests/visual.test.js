const { spawnSync } = require('child_process');
const path = require('path');

const scriptPath = path.join(__dirname, '..', 'bin', 'scan.js');

describe('Visual Output Snapshots', () => {
  test('should match snapshot for help command', () => {
    const child = spawnSync('node', [scriptPath, '--help'], { encoding: 'utf8', env: { ...process.env, FORCE_COLOR: '1' } });
    expect(child.stdout).toMatchSnapshot();
  });

  test('should match snapshot for version command', () => {
    const child = spawnSync('node', [scriptPath, '--version'], { encoding: 'utf8', env: { ...process.env, FORCE_COLOR: '1' } });
    // Version changes, so we match the format but maybe not the exact string if we want strict snapshot
    // But for now, let's snapshot it. If version changes, we update snapshot.
    expect(child.stdout).toMatchSnapshot();
  });
});
