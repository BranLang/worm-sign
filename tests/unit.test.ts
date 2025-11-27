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
    test('should fetch from all sources (excluding IBM) and deduplicate', async () => {
      const mockResponses: Record<string, string> = {
        'ibm': JSON.stringify({ packages: [{ name: 'pkg-ibm-only', version: '1.0.0' }] }),
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
          if (url.includes('ibm')) {
            stream.write(mockResponses['ibm']);
          } else if (url.includes('google')) { // Koi uses google docs
            stream.write(mockResponses['koi']);
          } else if (url.includes('datadog') || url.includes('github')) {
            stream.write(mockResponses['datadog']);
          }
          stream.end();
        });

        return { on: jest.fn(), setTimeout: jest.fn(), destroy: jest.fn() };
      });

      const result = await fetchBannedPackages({ source: 'all' });

      // Expected: pkg-b@2.0.0 (koi), pkg-a@1.0.0 (datadog), pkg-c@3.0.0 (datadog)
      // pkg-ibm-only should be excluded
      expect(result).toHaveLength(3);
      expect(result).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: 'pkg-b', version: '2.0.0' }),
        expect.objectContaining({ name: 'pkg-a', version: '1.0.0' }),
        expect.objectContaining({ name: 'pkg-c', version: '3.0.0' }),
      ]));
      expect(result).not.toEqual(expect.arrayContaining([
        expect.objectContaining({ name: 'pkg-ibm-only', version: '1.0.0' })
      ]));
    });

    test('should fetch from IBM when explicitly requested', async () => {
      const mockResponses: Record<string, string> = {
        'ibm': JSON.stringify({ packages: [{ name: 'pkg-a', version: '1.0.0' }] })
      };

      (https.get as jest.Mock).mockImplementation((url, options, callback) => {
        const stream = new PassThrough();
        // @ts-ignore
        stream.statusCode = 200;
        // @ts-ignore
        stream.headers = {};

        callback(stream);

        process.nextTick(() => {
          if (url.includes('ibm')) {
            stream.write(mockResponses['ibm']);
          }
          stream.end();
        });

        return { on: jest.fn(), setTimeout: jest.fn(), destroy: jest.fn() };
      });

      const result = await fetchBannedPackages({ source: 'ibm' });
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual(expect.objectContaining({ name: 'pkg-a', version: '1.0.0' }));
    });

    test('should handle partial failures', async () => {
      (https.get as jest.Mock).mockImplementation((url, options, callback) => {
        const stream = new PassThrough();

        if (url.includes('ibm')) {
          // @ts-ignore
          stream.statusCode = 500; // Fail IBM
        } else {
          // @ts-ignore
          stream.statusCode = 200;
        }
        // @ts-ignore
        stream.headers = {};

        callback(stream);

        process.nextTick(() => {
          if (!url.includes('ibm')) {
            if (url.includes('google')) {
              stream.write('name,version\npkg-b,2.0.0');
            } else {
              stream.write('package_name,package_version\npkg-c,3.0.0');
            }
          }
          stream.end();
        });

        return { on: jest.fn(), setTimeout: jest.fn(), destroy: jest.fn() };
      });

      const result = await fetchBannedPackages({ source: 'all' });

      // Should still have pkg-b and pkg-c
      expect(result).toHaveLength(2);
      expect(result).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: 'pkg-b', version: '2.0.0' }),
        expect.objectContaining({ name: 'pkg-c', version: '3.0.0' }),
      ]));
    });
  });
});
