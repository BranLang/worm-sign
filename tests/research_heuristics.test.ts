import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { analyzeScripts, scanProject } from '../src/index';

const TEST_DIR = path.join(__dirname, 'temp_research_test');

describe('Research Heuristics (Shai-Hulud 2.0)', () => {
  beforeAll(() => {
    if (!fs.existsSync(TEST_DIR)) {
      fs.mkdirSync(TEST_DIR);
    }
  });

  afterAll(() => {
    if (fs.existsSync(TEST_DIR)) {
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    }
  });

  describe('Script Analysis', () => {
    test('should detect destructive shred command', () => {
      const pkg = {
        scripts: {
          cleanup: 'shred -uvz -n 1 /home/user',
        },
      };
      const warnings = analyzeScripts(pkg);
      expect(warnings).toContain(
        "Suspicious script detected in 'cleanup': Known Malware Signature Match",
      );
    });

    test('should detect destructive Windows del command', () => {
      const pkg = {
        scripts: {
          cleanup: 'del /F /Q /S "%USERPROFILE%*"',
        },
      };
      const warnings = analyzeScripts(pkg);
      expect(warnings).toContain(
        "Suspicious script detected in 'cleanup': Known Malware Signature Match",
      );
    });

    test('should detect PowerShell Bun install', () => {
      const pkg = {
        scripts: {
          install: 'irm bun.sh/install.ps1|iex',
        },
      };
      const warnings = analyzeScripts(pkg);
      expect(warnings).toContain(
        "Suspicious script detected in 'install': Known Malware Signature Match",
      );
    });

    test('should detect C2 signature', () => {
      const pkg = {
        scripts: {
          postinstall: 'echo "Sha1-Hulud: The Second Coming"',
        },
      };
      const warnings = analyzeScripts(pkg);
      // "The Second Coming" is in the signatures list
      expect(warnings).toContain(
        "Suspicious script detected in 'postinstall': Known Malware Signature Match",
      );
    });
  });

  describe('Entropy Analysis', () => {
    test('should detect high entropy in large files', async () => {
      const malwareFile = 'bun_environment.js';
      const malwarePath = path.join(TEST_DIR, malwareFile);

      // Create a large file (> 5MB) with high entropy (random data)
      const size = 6 * 1024 * 1024; // 6MB
      const buffer = crypto.randomBytes(size);
      fs.writeFileSync(malwarePath, buffer);

      // Create a dummy package.json
      fs.writeFileSync(
        path.join(TEST_DIR, 'package.json'),
        JSON.stringify({ name: 'test-pkg', version: '1.0.0' }),
      );

      // Scan
      try {
        const result = await scanProject(TEST_DIR, []);
        const entropyWarning = result.warnings.find(
          (w) => w.includes('HIGH RISK file detected') && w.includes('High Entropy'),
        );
        expect(entropyWarning).toBeDefined();
        expect(entropyWarning).toContain(malwareFile);
      } catch {
        // scanProject might throw if no lockfile, but we are testing file scanning which happens before lockfile check?
        // Actually scanProject throws if no lockfile is found.
        // Let's create a dummy lockfile to satisfy it.
        fs.writeFileSync(
          path.join(TEST_DIR, 'package-lock.json'),
          JSON.stringify({
            name: 'test-pkg',
            version: '1.0.0',
            lockfileVersion: 2,
            packages: {},
          }),
        );

        const result = await scanProject(TEST_DIR, []);
        const entropyWarning = result.warnings.find(
          (w) => w.includes('HIGH RISK file detected') && w.includes('High Entropy'),
        );
        expect(entropyWarning).toBeDefined();
      }
    }, 30000);

    test('should NOT flag low entropy large files', async () => {
      const safeFile = 'bun_environment.js'; // Reusing name to trigger check, but content is safe
      const safePath = path.join(TEST_DIR, safeFile);

      // Create a large file (> 5MB) with low entropy (repeated char)
      const size = 6 * 1024 * 1024; // 6MB
      const buffer = Buffer.alloc(size, 'A');
      fs.writeFileSync(safePath, buffer);

      // Ensure package.json and lockfile exist (from previous test)
      if (!fs.existsSync(path.join(TEST_DIR, 'package.json'))) {
        fs.writeFileSync(
          path.join(TEST_DIR, 'package.json'),
          JSON.stringify({ name: 'test-pkg', version: '1.0.0' }),
        );
      }
      if (!fs.existsSync(path.join(TEST_DIR, 'package-lock.json'))) {
        fs.writeFileSync(
          path.join(TEST_DIR, 'package-lock.json'),
          JSON.stringify({
            name: 'test-pkg',
            version: '1.0.0',
            lockfileVersion: 2,
            packages: {},
          }),
        );
      }

      const result = await scanProject(TEST_DIR, []);
      const entropyWarning = result.warnings.find(
        (w) => w.includes('HIGH RISK file detected') && w.includes('High Entropy'),
      );
      expect(entropyWarning).toBeUndefined();

      // It might still be flagged as "Suspicious file" because of the name, but NOT "HIGH RISK ... High Entropy"
      const suspiciousWarning = result.warnings.find((w) => w.includes('Suspicious file detected'));
      expect(suspiciousWarning).toBeDefined();
    }, 30000);
  });
});
