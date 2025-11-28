import { isPrivateIp, validateUrl } from '../src/utils/validators';
import * as dns from 'dns';

jest.mock('dns');

describe('Validators', () => {
  describe('isPrivateIp', () => {
    test('should identify private IPv4 addresses', () => {
      expect(isPrivateIp('127.0.0.1')).toBe(true);
      expect(isPrivateIp('10.0.0.1')).toBe(true);
      expect(isPrivateIp('192.168.1.1')).toBe(true);
      expect(isPrivateIp('172.16.0.1')).toBe(true);
      expect(isPrivateIp('169.254.0.1')).toBe(true);
    });

    test('should identify public IPv4 addresses', () => {
      expect(isPrivateIp('8.8.8.8')).toBe(false);
      expect(isPrivateIp('1.1.1.1')).toBe(false);
      expect(isPrivateIp('172.32.0.1')).toBe(false); // Outside 172.16.0.0/12
    });

    test('should identify private IPv6 addresses', () => {
      expect(isPrivateIp('::1')).toBe(true);
      expect(isPrivateIp('fe80::1')).toBe(true);
      expect(isPrivateIp('fc00::1')).toBe(true);
    });

    test('should identify public IPv6 addresses', () => {
      expect(isPrivateIp('2001:4860:4860::8888')).toBe(false);
    });
  });

  describe('validateUrl', () => {
    test('should accept valid HTTPS URLs with public IPs', async () => {
      (dns.lookup as unknown as jest.Mock).mockImplementation((hostname, cb) => {
        cb(null, '8.8.8.8');
      });
      await expect(validateUrl('https://google.com')).resolves.not.toThrow();
    });

    test('should reject non-HTTPS URLs', async () => {
      await expect(validateUrl('http://google.com')).rejects.toThrow(
        'Only HTTPS protocol is allowed',
      );
    });

    test('should reject URLs resolving to private IPs', async () => {
      (dns.lookup as unknown as jest.Mock).mockImplementation((hostname, cb) => {
        cb(null, '127.0.0.1');
      });
      await expect(validateUrl('https://localhost')).rejects.toThrow('resolves to private IP');
    });

    test('should reject URLs with private IP hostnames', async () => {
      await expect(validateUrl('https://192.168.1.1')).rejects.toThrow('Access to private IP');
    });
  });
});
