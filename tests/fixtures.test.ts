import * as path from 'path';
import { scanProject } from '../src/index';

const FIXTURES_DIR = path.join(__dirname, 'fixtures');
const BANNED_LIST = path.join(__dirname, '..', 'sources', 'ibm.csv');

describe('Fixture Tests', () => {
  test('npm-ok should have no banned packages', async () => {
    const projectRoot = path.join(FIXTURES_DIR, 'npm-ok');
    const { matches } = await scanProject(projectRoot, BANNED_LIST);
    expect(matches).toHaveLength(0);
  });

  test('npm-banned should have banned packages', async () => {
    const projectRoot = path.join(FIXTURES_DIR, 'npm-banned');
    const { matches } = await scanProject(projectRoot, BANNED_LIST);
    expect(matches.length).toBeGreaterThan(0);
  });

  test('yarn-ok should have no banned packages', async () => {
    const projectRoot = path.join(FIXTURES_DIR, 'yarn-ok');
    const { matches } = await scanProject(projectRoot, BANNED_LIST);
    expect(matches).toHaveLength(0);
  });

  test('yarn-banned should have banned packages', async () => {
    const projectRoot = path.join(FIXTURES_DIR, 'yarn-banned');
    const { matches } = await scanProject(projectRoot, BANNED_LIST);
    expect(matches.length).toBeGreaterThan(0);
  });

  test('pnpm-ok should have no banned packages', async () => {
    const projectRoot = path.join(FIXTURES_DIR, 'pnpm-ok');
    const { matches } = await scanProject(projectRoot, BANNED_LIST);
    expect(matches).toHaveLength(0);
  });

  test('pnpm-banned should have banned packages', async () => {
    const projectRoot = path.join(FIXTURES_DIR, 'pnpm-banned');
    const { matches } = await scanProject(projectRoot, BANNED_LIST);
    expect(matches.length).toBeGreaterThan(0);
  });
  test('shai-hulud-files should detect malicious files and scripts', async () => {
    const fixturePath = path.join(FIXTURES_DIR, 'shai-hulud-files');
    const { warnings } = await scanProject(fixturePath, []);
    expect(warnings).toContain(
      "Suspicious file detected: 'setup_bun.js' (associated with Shai Hulud)",
    );
    expect(warnings).toContain(
      "Suspicious file detected: 'bun_environment.js' (associated with Shai Hulud)",
    );
    expect(warnings).toContain(
      "Suspicious script detected in 'preinstall': Shai Hulud malware script (node setup_bun.js)",
    );
  });
});
