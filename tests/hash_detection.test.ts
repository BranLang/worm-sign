import { scanProject } from '../src/index';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

describe('Hash-based Detection', () => {
  const tempDir = path.join(os.tmpdir(), 'worm-sign-hash-test');

  beforeAll(() => {
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir);
    }
  });

  afterAll(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  test('should detect a package by hash even if version does not match', async () => {
    const projectDir = path.join(tempDir, 'hash-project');
    if (!fs.existsSync(projectDir)) fs.mkdirSync(projectDir);

    const packageJson = {
      name: 'hash-project',
      version: '1.0.0',
      dependencies: {
        'safe-package': '1.0.0',
      },
    };
    fs.writeFileSync(path.join(projectDir, 'package.json'), JSON.stringify(packageJson, null, 2));

    // Mock lockfile with a "bad" hash for a "safe" package
    const badHash = 'sha512-badhashvalue';
    const packageLock = {
      name: 'hash-project',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        'node_modules/safe-package': {
          version: '1.0.0',
          integrity: badHash,
        },
      },
    };
    fs.writeFileSync(
      path.join(projectDir, 'package-lock.json'),
      JSON.stringify(packageLock, null, 2),
    );

    const bannedPackages = [
      { name: 'safe-package', version: '9.9.9', integrity: 'badhashvalue' }, // Version mismatch, but hash match
    ];

    const { matches } = await scanProject(projectDir, bannedPackages);

    expect(matches).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'safe-package',
          version: '1.0.0',
        }),
      ]),
    );
  });
});
