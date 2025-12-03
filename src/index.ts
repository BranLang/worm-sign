import * as fs from 'fs';
import * as crypto from 'crypto';
import * as path from 'path';
import * as https from 'https';
import { IncomingMessage } from 'http';

import Arborist from '@npmcli/arborist';
import { analyzeScripts } from './analysis';
export { analyzeScripts };
import { EntropyCalculator } from './heuristics/entropy';
import { MALWARE_FILENAMES } from './generated/signatures';
import { CompromisedPackage, ScanMatch } from './types';
import { validateUrl } from './utils/validators';

import { loadCsv, parseCsv } from './utils/csv';
import yarnHandler from './package-managers/yarn';
import pnpmHandler from './package-managers/pnpm';
export { loadCsv, parseCsv };
export { loadConfig } from './config';
export type { WormSignConfig } from './config';

export function loadJson(filePath: string): CompromisedPackage[] {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const json = JSON.parse(raw);
    if (Array.isArray(json)) {
      // Handle array of packages directly
      return json as CompromisedPackage[];
    }
    if (json.packages && Array.isArray(json.packages)) {
      return json.packages as CompromisedPackage[];
    }
    console.warn(
      `Warning: JSON at ${filePath} does not contain a "packages" array or is not an array.`,
    );
    return [];
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.warn(`Warning: Failed to parse JSON ${filePath}: ${msg}`);
    return [];
  }
}

export interface SourceConfig {
  url: string;
  type: 'json' | 'csv';
  name?: string;
  insecure?: boolean;
}

export const SOURCES: Record<string, SourceConfig> = {
  datadog: {
    url: 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv',
    type: 'csv',
  },
  koi: {
    url: 'https://docs.google.com/spreadsheets/d/16aw6s7mWoGU7vxBciTEZSaR5HaohlBTfVirvI-PypJc/export?format=csv&gid=1289659284',
    type: 'csv',
  },
  // TODO: Update IBM URL as it is currently returning 404
  /*
  ibm: {
    url: 'https://raw.githubusercontent.com/IBM/security-intelligence/master/threat-intel/shai-hulud.csv',
    type: 'csv',
  },
  */
};

export function fetchFromApi(sourceConfig: {
  url: string;
  type: string;
  insecure?: boolean;
}): Promise<CompromisedPackage[]> {
  const { url, type, insecure } = sourceConfig;
  if (!url || !type) {
    return Promise.reject(new Error('Invalid source configuration: missing url or type'));
  }

  const fetchUrl = async (targetUrl: string, attempt = 1): Promise<CompromisedPackage[]> => {
    // SSRF Protection: Resolve and validate IP first
    const resolvedIp = await validateUrl(targetUrl);
    const urlObj = new URL(targetUrl);

    return new Promise((resolve, reject) => {
      if (attempt > 5) {
        reject(new Error('Too many redirects'));
        return;
      }

      const options: https.RequestOptions = {
        hostname: resolvedIp,
        port: urlObj.port || 443,
        path: urlObj.pathname + urlObj.search,
        servername: urlObj.hostname, // SNI
        headers: {
          Host: urlObj.hostname, // Host header
          Accept: type === 'json' ? 'application/json' : 'text/csv',
          'User-Agent': 'worm-sign',
        },
        rejectUnauthorized: !insecure,
      };

      const req = https.get(options, (res: IncomingMessage) => {
        if (
          res.statusCode &&
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          // Follow redirect
          const redirectUrl = res.headers.location;
          if (!redirectUrl) {
            reject(new Error('Redirect without location header'));
            return;
          }
          // Recursive call will validate the new URL
          fetchUrl(redirectUrl, attempt + 1)
            .then(resolve)
            .catch(reject);
          return;
        }

        if (res.statusCode && res.statusCode !== 200) {
          reject(new Error(`API request failed with status ${res.statusCode}`));
          res.resume(); // Consume response
          return;
        }
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try {
            if (type === 'json') {
              const json = JSON.parse(data);
              if (!Array.isArray(json.packages)) {
                reject(new Error('Invalid API response: "packages" field must be an array.'));
                return;
              }
              resolve(json.packages);
            } else if (type === 'csv') {
              resolve(parseCsv(data));
            }
          } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            reject(new Error(`Failed to parse API response: ${msg}`));
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(5000, () => {
        req.destroy();
        reject(new Error('API request timed out after 5000ms'));
      });
    });
  };

  return fetchUrl(url);
}

export async function fetchCompromisedPackages(
  sources: SourceConfig[],
): Promise<{ packages: CompromisedPackage[]; errors: string[] }> {
  const allPackages: CompromisedPackage[] = [];
  const errors: string[] = [];

  for (const config of sources) {
    const name = config.name || config.url;
    try {
      const pkgs = await fetchFromApi(config);
      allPackages.push(...pkgs);
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      errors.push(`Failed to fetch from ${name}: ${msg}`);
    }
  }

  if (allPackages.length === 0 && errors.length > 0) {
    // If everything failed, we still return the errors, but maybe we should let the caller decide if it's fatal?
    // The caller (CLI) will see 0 packages and N errors.
  }

  // Deduplicate
  const uniqueMap = new Map<string, CompromisedPackage>();
  allPackages.forEach((p) => {
    const key = `${p.name}@${p.version}`;
    if (!uniqueMap.has(key)) {
      uniqueMap.set(key, p);
    }
  });

  return { packages: Array.from(uniqueMap.values()), errors };
}

interface CompromisedInfo {
  versions: Set<string>;
  wildcard: boolean;
  hashes: Set<string>;
}

function buildCompromisedMap(entries: CompromisedPackage[]): Map<string, CompromisedInfo> {
  const map = new Map<string, CompromisedInfo>();
  for (const { name, version } of entries) {
    if (!name) continue;
    const info = map.get(name) ?? { versions: new Set(), wildcard: false, hashes: new Set() };
    const ver = version?.trim();
    if (!ver || ver === '*' || ver.toLowerCase() === 'any') {
      info.wildcard = true;
    } else {
      info.versions.add(ver);
    }
    const entry = entries.find((e) => e.name === name && e.version === version);
    if (entry?.integrity) {
      info.hashes.add(entry.integrity);
    }
    map.set(name, info);
  }
  return map;
}

function shouldFlag(
  compromisedInfo: CompromisedInfo | undefined,
  version: string,
  integrity?: string | null,
): boolean {
  if (!compromisedInfo) return false;
  if (compromisedInfo.wildcard) return true;
  if (compromisedInfo.versions.has(version)) return true;
  if (integrity && compromisedInfo.hashes.size > 0) {
    for (const hash of compromisedInfo.hashes) {
      if (integrity.includes(hash)) return true;
    }
  }
  return false;
}

/**
 * Scans the project for compromised packages using @npmcli/arborist.
 * @param {string} projectRoot - The root directory of the project.
 * @param {string|Array} compromisedListSource - Path to the CSV file OR an array of compromised package objects.
 * @param {Object} [options] - Optional settings.
 * @param {boolean} [options.debug] - Enable debug logging.
 * @returns {Promise<{ matches: Array<{name: string, version: string, section: string}>, warnings: string[] }>}
 */
import { Finding } from './types';
import { WormSignConfig } from './config';

export async function scanProject(
  projectRoot: string,
  compromisedListSource: string | CompromisedPackage[],
  options?: { debug?: boolean; config?: WormSignConfig },
) {
  const debug = (msg: string) => {
    if (options?.debug) console.log(`[DEBUG] ${msg}`);
  };

  const resolvedRoot = path.resolve(projectRoot);
  debug(`Scanning project at: ${resolvedRoot}`);

  if (!fs.existsSync(resolvedRoot)) {
    throw new Error(`Project root does not exist: ${resolvedRoot}`);
  }

  const packageJsonPath = path.join(resolvedRoot, 'package.json');
  const allWarnings: string[] = [];
  const allFindings: Finding[] = [];

  let compromisedEntries: CompromisedPackage[];
  if (Array.isArray(compromisedListSource)) {
    compromisedEntries = compromisedListSource;
  } else if (typeof compromisedListSource === 'string') {
    if (!fs.existsSync(compromisedListSource)) {
      throw new Error(`Compromised list not found at ${compromisedListSource}`);
    }
    compromisedEntries = loadCsv(compromisedListSource);
  } else {
    throw new Error('Invalid compromised list source. Must be a file path or an array.');
  }

  if (!fs.existsSync(packageJsonPath)) {
    throw new Error(`package.json not found at ${packageJsonPath}`);
  }

  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  debug('Loaded package.json');

  // 1. Analyze Root Scripts
  const scriptFindings = analyzeScripts(packageJson, options?.config);
  allFindings.push(...scriptFindings);
  // Backwards compatibility: push messages to warnings
  scriptFindings.forEach((f) => allWarnings.push(f.message));

  // 2. Check for known malware files in root
  const KNOWN_MALWARE_HASHES = new Set([
    'a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a', // setup_bun.js
    '62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0', // bun_environment.js
    'cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd', // bun_environment.js
    'f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068', // bun_environment.js
  ]);

  for (const file of MALWARE_FILENAMES) {
    const filePath = path.join(resolvedRoot, file);
    if (fs.existsSync(filePath)) {
      try {
        const stats = fs.statSync(filePath);
        const isLarge = stats.size > 5 * 1024 * 1024;

        const hash = crypto.createHash('sha256');
        // Only calculate entropy if file is large (optimization)
        const entropyCalc = isLarge ? new EntropyCalculator() : null;

        const stream = fs.createReadStream(filePath);

        await new Promise<void>((resolve, reject) => {
          stream.on('data', (chunk) => {
            hash.update(chunk);
            if (entropyCalc) {
              entropyCalc.update(chunk);
            }
          });
          stream.on('error', reject);
          stream.on('end', resolve);
        });

        const finalHash = hash.digest('hex');

        if (KNOWN_MALWARE_HASHES.has(finalHash)) {
          allWarnings.push(`CONFIRMED MALWARE file detected: '${file}' (Hash match: ${finalHash})`);
        } else if (isLarge && entropyCalc) {
          const entropy = entropyCalc.digest();
          // Threshold 7.0 for packed malware in JS context
          if (entropy > 7.0) {
            allWarnings.push(
              `HIGH RISK file detected: '${file}' (High Entropy: ${entropy.toFixed(2)}, Size: ${stats.size} bytes)`,
            );
          }
          allWarnings.push(`Suspicious file detected: '${file}' (associated with Shai Hulud)`);
        } else {
          allWarnings.push(`Suspicious file detected: '${file}' (associated with Shai Hulud)`);
        }
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        allWarnings.push(
          `Suspicious file detected: '${file}' (associated with Shai Hulud) - could not read: ${msg}`,
        );
      }
    }
  }

  // 3. Scan Dependencies
  const compromisedMap = buildCompromisedMap(compromisedEntries);
  const matches: ScanMatch[] = [];

  let treeLoaded = false;

  // Try npm (Arborist) first
  try {
    const arb = new Arborist({ path: resolvedRoot });
    const tree = await arb.loadVirtual();
    debug(`Loaded dependency tree with ${tree.inventory.size} nodes.`);
    treeLoaded = true;

    for (const node of tree.inventory.values()) {
      const { name, version, integrity } = node;
      const info = compromisedMap.get(name);

      if (shouldFlag(info, version, integrity)) {
        const section = node.dev ? 'devDependencies' : 'dependencies';
        matches.push({ name, version, section });
      }
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    debug(`Arborist failed: ${msg}`);
    // If it's not a missing lockfile error, rethrow
    if (!msg.includes('ENOENT') && !msg.includes('lockfile') && !msg.includes('shrinkwrap')) {
      throw new Error(`Failed to load dependency tree: ${msg}`);
    }
  }

  // Fallback to Yarn or pnpm if npm failed
  if (!treeLoaded) {
    debug('Checking for Yarn or pnpm lockfiles...');
    const handlers = [yarnHandler, pnpmHandler];
    let handlerFound = false;

    for (const handler of handlers) {
      const lockFile = handler.findLockFile(resolvedRoot);
      if (lockFile) {
        debug(`Found ${handler.label} lockfile: ${lockFile}`);
        handlerFound = true;
        const result = handler.loadLockPackages(lockFile);

        if (!result.success) {
          result.warnings.forEach((w) => allWarnings.push(w));
          continue;
        }

        // Iterate over loaded packages
        for (const [name, versions] of result.packages.entries()) {
          const info = compromisedMap.get(name);
          if (!info) continue;

          for (const version of versions) {
            // Get integrity if available
            let integrity: string | undefined;
            if (result.packageIntegrity) {
              const pkgIntegrity = result.packageIntegrity.get(name);
              if (pkgIntegrity) {
                integrity = pkgIntegrity.get(version);
              }
            }

            if (shouldFlag(info, version, integrity)) {
              matches.push({ name, version, section: 'locked' });
            }
          }
        }
        break; // Stop after first successful handler
      }
    }

    if (!handlerFound) {
      throw new Error(
        'No lockfile found (package-lock.json, yarn.lock, pnpm-lock.yaml). Please install dependencies.',
      );
    }
  }

  return { matches, warnings: allWarnings, findings: allFindings };
}
