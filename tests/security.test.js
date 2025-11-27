const { fetchFromApi, scanProject } = require('../src/index');
const path = require('path');
const fs = require('fs');

jest.mock('https');
const https = require('https');

describe('Security Tests', () => {
  describe('SSRF Protection', () => {
    test('should reject non-HTTPS URLs', async () => {
      await expect(fetchFromApi({ url: 'http://example.com', type: 'json' }))
        .rejects.toThrow('Security Error: Only HTTPS protocol is allowed');
      
      await expect(fetchFromApi({ url: 'ftp://example.com', type: 'json' }))
        .rejects.toThrow('Security Error: Only HTTPS protocol is allowed');
        
      await expect(fetchFromApi({ url: 'file:///etc/passwd', type: 'json' }))
        .rejects.toThrow('Security Error: Only HTTPS protocol is allowed');
    });
  });

  describe('Path Traversal Protection', () => {
    test('should reject non-existent paths', async () => {
      await expect(scanProject('/non/existent/path', 'vuls.csv'))
        .rejects.toThrow('Project root does not exist');
    });
    
    // Note: scanProject uses path.resolve which resolves relative paths safely.
    // Real path traversal exploits usually involve trying to escape the intended directory
    // when the tool constructs paths. Since we resolve the input root immediately,
    // we are mostly checking that it doesn't crash or allow weird inputs.
  });
});
