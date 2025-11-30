import * as dns from 'dns';
import * as net from 'net';
import { URL } from 'url';

export function isPrivateIp(ip: string): boolean {
  if (net.isIP(ip) === 0) return false;

  // IPv4 Private Ranges
  // 10.0.0.0/8
  // 172.16.0.0/12
  // 192.168.0.0/16
  // 127.0.0.0/8 (Loopback)
  // 169.254.0.0/16 (Link-local)

  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    return false;
  }

  // IPv6 Private Ranges
  // fc00::/7 (Unique Local)
  // fe80::/10 (Link-local)
  // ::1/128 (Loopback)
  if (net.isIPv6(ip)) {
    // Simplified check for common private prefixes
    // Normalize? net.isIPv6 handles format, but we need to check ranges.
    // For now, let's block loopback and link-local which are most critical for SSRF against local services.
    if (ip === '::1') return true;
    if (ip.toLowerCase().startsWith('fe80:')) return true;
    if (ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) return true;
    return false;
  }

  return false;
}

export async function validateUrl(urlStr: string): Promise<string> {
  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    throw new Error(`Invalid URL: ${urlStr}`);
  }

  if (parsed.protocol !== 'https:') {
    throw new Error('Security Error: Only HTTPS protocol is allowed.');
  }

  const hostname = parsed.hostname;

  // If hostname is an IP, check directly
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new Error(`Security Error: Access to private IP ${hostname} is forbidden.`);
    }
    return hostname;
  }

  // Resolve hostname
  return new Promise((resolve, reject) => {
    dns.lookup(hostname, (err, address) => {
      if (err) {
        reject(new Error(`DNS lookup failed for ${hostname}: ${err.message}`));
        return;
      }
      if (isPrivateIp(address)) {
        reject(
          new Error(`Security Error: Hostname ${hostname} resolves to private IP ${address}.`),
        );
        return;
      }
      resolve(address);
    });
  });
}
