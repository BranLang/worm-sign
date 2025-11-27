const { loadCsv, fetchFromApi } = require('../src/index');
const path = require('path');
const fs = require('fs');

jest.mock('https');
const https = require('https');
const { PassThrough } = require('stream');

describe('Unit Tests', () => {
  describe('loadCsv', () => {
    test('should parse CSV correctly', () => {
      const csvContent = 'name,version\npackage-a,1.0.0\npackage-b,2.0.0';
      const filePath = path.join(__dirname, 'temp.csv');
      fs.writeFileSync(filePath, csvContent);

      const result = loadCsv(filePath);
      expect(result).toEqual([
        { name: 'package-a', version: '1.0.0' },
        { name: 'package-b', version: '2.0.0' },
      ]);

      fs.unlinkSync(filePath);
    });

    test('should handle empty lines and comments', () => {
        // Our current CSV parser is simple, let's test its limits or expected behavior
        // Based on src/index.js implementation:
        // .filter((line) => line.length > 0)
        // It doesn't seem to explicitly handle comments in loadCsv -> parseCsv, 
        // but fetchFromApi's CSV parser does. 
        // Let's stick to the implementation of parseCsv in src/index.js:
        /*
        function parseCsv(raw) {
          return raw
            .split(/\r?\n/)
            .slice(1)
            .map((line) => line.trim())
            .filter((line) => line.length > 0)
            .map((line) => {
              const [name, version] = line.split(',').map((segment) => segment?.trim());
              return { name, version: version || '' };
            })
            .filter(({ name }) => !!name);
        }
        */
       const csvContent = 'name,version\n\npackage-a, 1.0.0 \n  package-b,';
       const filePath = path.join(__dirname, 'temp_complex.csv');
       fs.writeFileSync(filePath, csvContent);
 
       const result = loadCsv(filePath);
       expect(result).toEqual([
         { name: 'package-a', version: '1.0.0' },
         { name: 'package-b', version: '' },
       ]);
 
       fs.unlinkSync(filePath);
    });
  });

  describe('fetchFromApi', () => {
      // We need to mock https.get
      test('should fetch and parse JSON', async () => {
          const mockResponse = new PassThrough();
          mockResponse.statusCode = 200;
          mockResponse.headers = {};
          
          https.get.mockImplementation((url, options, callback) => {
              callback(mockResponse);
              return { on: jest.fn(), setTimeout: jest.fn(), destroy: jest.fn() };
          });

          const promise = fetchFromApi({ url: 'http://example.com', type: 'json' });
          
          mockResponse.write(JSON.stringify({ packages: [{ name: 'bad-pkg', version: '1.0.0' }] }));
          mockResponse.end();

          const result = await promise;
          expect(result).toEqual([{ name: 'bad-pkg', version: '1.0.0' }]);
      });

      test('should fetch and parse CSV', async () => {
        const mockResponse = new PassThrough();
        mockResponse.statusCode = 200;
        mockResponse.headers = {};
        
        https.get.mockImplementation((url, options, callback) => {
            callback(mockResponse);
            return { on: jest.fn(), setTimeout: jest.fn(), destroy: jest.fn() };
        });

        const promise = fetchFromApi({ url: 'http://example.com', type: 'csv' });
        
        mockResponse.write('name,version\nbad-pkg,1.0.0');
        mockResponse.end();

        const result = await promise;
        expect(result).toEqual([{ name: 'bad-pkg', version: '1.0.0', reason: 'Banned by Koi Security Feed' }]);
    });
  });
});
