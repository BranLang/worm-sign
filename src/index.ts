import * as fs from 'fs';
import * as crypto from 'crypto';
import * as path from 'path';
import * as https from 'https';
import { IncomingMessage } from 'http';
import { parse } from 'csv-parse/sync';
import pnpm from './package-managers/pnpm';
import yarn from './package-managers/yarn';
import npm from './package-managers/npm';
import { CompromisedPackage, PackageManagerHandler, ScanMatch } from './types';
import { validateUrl } from './utils/validators';

const packageManagers: PackageManagerHandler[] = [pnpm, yarn, npm];

import { loadCsv, parseCsv } from './utils/csv';

export function loadJson(filePath: string): CompromisedPackage[] {
  const raw = fs.readFileSync(filePath, 'utf8');
  try {
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
  } catch (e: any) {
    console.warn(`Warning: Failed to parse JSON ${filePath}: ${e.message}`);
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
    // SSRF Protection
    await validateUrl(targetUrl);

    return new Promise((resolve, reject) => {
      if (attempt > 5) {
        reject(new Error('Too many redirects'));
        return;
      }
      const options: https.RequestOptions = {
        headers: {
          Accept: type === 'json' ? 'application/json' : 'text/csv',
          'User-Agent': 'worm-sign',
        },
        rejectUnauthorized: !insecure,
      };
      const req = https.get(targetUrl, options, (res: IncomingMessage) => {
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
          } catch (e: any) {
            reject(new Error(`Failed to parse API response: ${e.message}`));
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
    } catch (error: any) {
      errors.push(`Failed to fetch from ${name}: ${error.message}`);
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

function collectPackages(pkgJson: any): Map<string, { section: string; version: string }> {
  const sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];

  const results = new Map<string, { section: string; version: string }>();

  for (const section of sections) {
    const entries = pkgJson[section];
    if (!entries) continue;
    for (const [name, version] of Object.entries(entries) as [string, string][]) {
      results.set(name, { section, version });
    }
  }

  return results;
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
    // @ts-ignore
    if (entries.find((e) => e.name === name && e.version === version)?.integrity) {
      // @ts-ignore
      info.hashes.add(entries.find((e) => e.name === name && e.version === version)?.integrity);
    }
    map.set(name, info);
  }
  return map;
}

function shouldFlag(
  compromisedInfo: CompromisedInfo | undefined,
  version: string,
  integrity?: string,
): boolean {
  if (!compromisedInfo) return false;
  if (compromisedInfo.wildcard) return true;
  if (compromisedInfo.versions.has(version)) return true;
  if (integrity && compromisedInfo.hashes.size > 0) {
    // Check if any banned hash matches the package integrity
    // Integrity strings are usually "algo-hash", e.g. "sha512-..."
    // We should check if the banned hash is contained in the integrity string
    for (const hash of compromisedInfo.hashes) {
      if (integrity.includes(hash)) return true;
    }
  }
  return false;
}

function findLockForHandler(projectRoot: string, handler: PackageManagerHandler): string | null {
  if (typeof handler.findLockFile === 'function') {
    const resolved = handler.findLockFile(projectRoot);
    if (resolved) return resolved;
  }

  if (Array.isArray(handler.lockFiles)) {
    for (const fileName of handler.lockFiles) {
      const candidate = path.join(projectRoot, fileName);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
  }

  return null;
}

function detectPackageManager(projectRoot: string, packageJson: any) {
  const warnings: string[] = [];
  const packageManagerField = packageJson?.packageManager;
  let preferred: PackageManagerHandler | null = null;

  if (packageManagerField) {
    preferred =
      packageManagers.find(
        (handler) =>
          typeof handler.detectFromPackageManagerField === 'function' &&
          handler.detectFromPackageManagerField(packageManagerField),
      ) || null;
  }

  const available = packageManagers
    .map((handler) => ({ handler, lockPath: findLockForHandler(projectRoot, handler) }))
    .filter((entry) => !!entry.lockPath);

  if (preferred) {
    const preferredLockPath = findLockForHandler(projectRoot, preferred);
    if (preferredLockPath) {
      return { handler: preferred, lockPath: preferredLockPath, warnings };
    }

    if (available.length > 0) {
      const fallback = available[0];
      warnings.push(
        `package.json declares ${preferred.label ?? preferred.id}, but its lockfile is missing; falling back to ${fallback.handler.label ?? fallback.handler.id}.`,
      );
      // @ts-ignore
      return { handler: fallback.handler, lockPath: fallback.lockPath, warnings };
    }

    warnings.push(
      `package.json declares ${preferred.label ?? preferred.id}, but no matching lockfile was found.`,
    );
    return { handler: preferred, lockPath: null, warnings };
  }

  if (available.length === 1) {
    // @ts-ignore
    return { handler: available[0].handler, lockPath: available[0].lockPath, warnings };
  }

  if (available.length > 1) {
    const names = available.map((entry) => entry.handler.label ?? entry.handler.id).join(', ');
    warnings.push(
      `Multiple lockfiles detected (${names}); defaulting to ${available[0].handler.label ?? available[0].handler.id}.`,
    );
    // @ts-ignore
    return { handler: available[0].handler, lockPath: available[0].lockPath, warnings };
  }

  return { handler: null, lockPath: null, warnings };
}

export function analyzeScripts(pkgJson: any): string[] {
  const warnings: string[] = [];
  const scripts = pkgJson.scripts || {};
  const SUSPICIOUS_PATTERNS = [
    { regex: /(curl|wget)\s+/, label: 'Network request (curl/wget)' },
    { regex: /\|\s*bash/, label: 'Pipe to bash' },
    { regex: /[A-Za-z0-9+/]{60,}={0,2}/, label: 'Potential Base64 encoded string' },
    { regex: /\\x[0-9a-fA-F]{2}/, label: 'Hex escape sequence (obfuscation)' },
    { regex: /eval\s*\(/, label: 'Use of eval()' },
    { regex: /rm\s+(-rf|-fr)\s+[\s\S]*/, label: 'Destructive command (rm -rf)' },
    { regex: /nc\s+.*-e\s+/, label: 'Netcat reverse shell' },
    { regex: /(python|perl|ruby|node|sh|bash)\s+-[ce]\s+/, label: 'Inline code execution' },
    { regex: /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/, label: 'IP address detected' },
    { regex: /bun\.sh/, label: 'Suspicious domain (bun.sh) - associated with Shai Hulud' },
    { regex: /node\s+setup_bun\.js/, label: 'Shai Hulud malware script (node setup_bun.js)' },
  ];

  for (const [name, script] of Object.entries(scripts) as [string, string][]) {
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.regex.test(script)) {
        warnings.push(`Suspicious script detected in '${name}': ${pattern.label}`);
      }
    }
  }
  return warnings;
}

/**
 * Scans the project for compromised packages.
 * @param {string} projectRoot - The root directory of the project.
 * @param {string|Array} compromisedListSource - Path to the CSV file OR an array of compromised package objects.
 * @param {Object} [options] - Optional settings.
 * @param {boolean} [options.debug] - Enable debug logging.
 * @returns {Promise<{ matches: Array<{name: string, version: string, section: string}>, warnings: string[] }>}
 */
export async function scanProject(
  projectRoot: string,
  compromisedListSource: string | CompromisedPackage[],
  options?: { debug?: boolean },
) {
  const debug = (msg: string) => {
    if (options?.debug) console.log(`[DEBUG] ${msg}`);
  };

  // Input Validation: Path Traversal Protection
  const resolvedRoot = path.resolve(projectRoot);
  debug(`Scanning project at: ${resolvedRoot}`);
  // Ensure resolved path is still within expected bounds if necessary,
  // but for a CLI tool scanning a user-provided path, resolve is usually enough to handle relative paths safely.
  // We can check if it exists here.
  if (!fs.existsSync(resolvedRoot)) {
    throw new Error(`Project root does not exist: ${resolvedRoot}`);
  }

  const packageJsonPath = path.join(resolvedRoot, 'package.json');
  const allWarnings: string[] = [];

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

  // Heuristic Analysis
  const scriptWarnings = analyzeScripts(packageJson);
  allWarnings.push(...scriptWarnings);

  // Check for known malware files
  const MALWARE_FILES = ['setup_bun.js', 'bun_environment.js'];
  const KNOWN_MALWARE_HASHES = new Set([
    'a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a', // setup_bun.js
    '62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0', // bun_environment.js
    'cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd', // bun_environment.js
    'f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068', // bun_environment.js
    'f1df4896244500671eb4aa63ebb48ea11cee196fafaa0e9874e17b24ac053c02', // OSINT
    '9d59fd0bcc14b671079824c704575f201b74276238dc07a9c12a93a84195648a', // OSINT
    'e0250076c1d2ac38777ea8f542431daf61fcbaab0ca9c196614b28065ef5b918', // OSINT
  ]);

  for (const file of MALWARE_FILES) {
    const filePath = path.join(resolvedRoot, file);
    if (fs.existsSync(filePath)) {
      try {
        const fileBuffer = fs.readFileSync(filePath);
        const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        if (KNOWN_MALWARE_HASHES.has(hash)) {
          allWarnings.push(`CONFIRMED MALWARE file detected: '${file}' (Hash match: ${hash})`);
        } else {
          allWarnings.push(`Suspicious file detected: '${file}' (associated with Shai Hulud)`);
        }
      } catch {
        allWarnings.push(
          `Suspicious file detected: '${file}' (associated with Shai Hulud) - could not read hash`,
        );
      }
    }
  }

  const compromisedMap = buildCompromisedMap(compromisedEntries);
  const declaredPackages = collectPackages(packageJson);
  debug(`Found ${declaredPackages.size} declared dependencies.`);

  const detection = detectPackageManager(projectRoot, packageJson);
  if (detection.warnings) {
    allWarnings.push(...detection.warnings);
  }

  if (!detection.handler) {
    throw new Error(
      'Unable to determine which package manager to inspect. Add a lockfile or set the packageManager field in package.json.',
    );
  }

  if (!detection.lockPath) {
    throw new Error(
      `Detected ${detection.handler.label ?? detection.handler.id}, but no lockfile was found. Please generate a lockfile and retry.`,
    );
  }

  const {
    packages: lockPackages = new Map(),
    packageIntegrity: lockIntegrity = new Map(),
    warnings: lockWarnings = [],
    success,
  } = detection.handler.loadLockPackages(detection.lockPath);
  debug(`Loaded ${lockPackages.size} packages from lockfile: ${detection.lockPath}`);

  if (lockWarnings) {
    allWarnings.push(...lockWarnings);
  }

  if (!success) {
    throw new Error('Unable to analyse the dependency lockfile.');
  }

  const matches: ScanMatch[] = [];
  const seen = new Set();

  for (const [name, info] of compromisedMap.entries()) {
    const versions = lockPackages.get(name);
    if (!versions || versions.size === 0) continue;

    for (const version of versions) {
      const integrity = lockIntegrity.get(name)?.get(version);
      if (!shouldFlag(info, version, integrity)) continue;
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const declared = declaredPackages.get(name);
      const section = declared ? declared.section : 'transitive';
      matches.push({ name, version, section });
    }
  }

  return { matches, warnings: allWarnings };
}
