import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import { IncomingMessage } from 'http';
import { parse } from 'csv-parse/sync';
import pnpm from './package-managers/pnpm';
import yarn from './package-managers/yarn';
import npm from './package-managers/npm';
import { BannedPackage, PackageManagerHandler, LockPackageResult, ScanMatch } from './types';
import { validateUrl } from './utils/validators';

const packageManagers: PackageManagerHandler[] = [
  pnpm,
  yarn,
  npm,
];

export function loadCsv(filePath: string): BannedPackage[] {
  const raw = fs.readFileSync(filePath, 'utf8');
  return parseCsv(raw);
}

function parseCsv(raw: string): BannedPackage[] {
  try {
    const records = parse(raw, {
      columns: ['name', 'version', 'reason'],
      skip_empty_lines: true,
      relax_column_count: true,
      trim: true,
      from_line: 2 // Skip header assuming standard format, or we can use columns: true if header is reliable
    });
    // If columns option is used, records are objects.
    // However, the input CSV might vary.
    // The original code handled "package name,package version" header.
    // Let's use a more robust approach:
    // If we use columns: true, it uses the first line as header.
    // But the header might be "package name" or "name".

    // Let's stick to the original logic's intent but use csv-parse for tokenization.
    // Actually, let's use columns: true and map keys.

    const parsed = parse(raw, {
      columns: true,
      skip_empty_lines: true,
      trim: true,
      relax_column_count: true
    });

    return parsed.map((record: any) => {
      // Try to find name and version fields
      const name = record['package name'] || record['name'] || record['Package Name'] || record['package_name'] || Object.values(record)[0];
      const version = record['package version'] || record['version'] || record['Package Version'] || record['package_version'] || Object.values(record)[1] || '';
      const reason = record['MSC ID'] || record['reason'] || '';

      return { name, version, reason };
    }).filter((p: any) => !!p.name) as BannedPackage[];

  } catch (e) {
    // Fallback or rethrow?
    // If strict parsing fails, maybe try simple split?
    // But we want to fix the vulnerability, so we should rely on the parser.
    console.warn('CSV parse warning:', e);
    return [];
  }
}

export const SOURCES: Record<string, { url: string; type: 'json' | 'csv' }> = {
  ibm: {
    url: 'https://datalake-rest-api.cio-devex-data-lake.dal.app.cirrus.ibm.com/v1/ciso/vulnerable-packages',
    type: 'json',
  },
  koi: {
    url: 'https://docs.google.com/spreadsheets/d/16aw6s7mWoGU7vxBciTEZSaR5HaohlBTfVirvI-PypJc/export?format=csv&gid=1289659284',
    type: 'csv',
  },
  datadog: {
    url: 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/shai-hulud-2.0.csv',
    type: 'csv',
  },
};

export function fetchFromApi(sourceConfig: { url: string; type: string }): Promise<BannedPackage[]> {
  const { url, type } = sourceConfig;
  if (!url || !type) {
    return Promise.reject(new Error('Invalid source configuration: missing url or type'));
  }

  const fetchUrl = async (targetUrl: string, attempt = 1): Promise<BannedPackage[]> => {
    // SSRF Protection
    await validateUrl(targetUrl);

    return new Promise((resolve, reject) => {
      if (attempt > 5) {
        reject(new Error('Too many redirects'));
        return;
      }
      const req = https.get(targetUrl, { headers: { 'Accept': type === 'json' ? 'application/json' : 'text/csv' } }, (res: IncomingMessage) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          // Follow redirect
          // Validate redirect URL
          const redirectUrl = res.headers.location;
          if (!redirectUrl) {
            reject(new Error('Redirect without location header'));
            return;
          }
          // Recursive call will validate the new URL
          fetchUrl(redirectUrl, attempt + 1).then(resolve).catch(reject);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`API request failed with status ${res.statusCode}`));
          return;
        }
        let data = '';
        res.on('data', (chunk) => data += chunk);
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

export async function fetchBannedPackages(options: { source?: string, url?: string, type?: string }): Promise<BannedPackage[]> {
  let sourcesToFetch: { name: string, config: { url: string, type: string } }[] = [];

  if (options.url) {
    sourcesToFetch.push({ name: 'custom', config: { url: options.url, type: options.type || 'json' } });
  } else if (options.source === 'all') {
    sourcesToFetch = Object.entries(SOURCES)
      .filter(([name]) => name !== 'ibm')
      .map(([name, config]) => ({ name, config }));
  } else {
    const sourceKey = options.source || 'all'; // Default to all if undefined, though CLI handles default
    if (sourceKey === 'all') {
      sourcesToFetch = Object.entries(SOURCES)
        .filter(([name]) => name !== 'ibm')
        .map(([name, config]) => ({ name, config }));
    } else {
      const config = SOURCES[sourceKey];
      if (!config) {
        throw new Error(`Unknown source '${sourceKey}'. Available sources: ${Object.keys(SOURCES).join(', ')}`);
      }
      sourcesToFetch.push({ name: sourceKey, config });
    }
  }

  const allPackages: BannedPackage[] = [];
  const errors: string[] = [];

  for (const { name, config } of sourcesToFetch) {
    try {
      const pkgs = await fetchFromApi(config);
      allPackages.push(...pkgs);
    } catch (error: any) {
      errors.push(`Failed to fetch from ${name}: ${error.message}`);
    }
  }

  if (allPackages.length === 0 && errors.length > 0) {
    throw new Error(errors.join('; '));
  }

  // Deduplicate
  const uniqueMap = new Map<string, BannedPackage>();
  allPackages.forEach(p => {
    const key = `${p.name}@${p.version}`;
    if (!uniqueMap.has(key)) {
      uniqueMap.set(key, p);
    }
  });

  return Array.from(uniqueMap.values());
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

interface BannedInfo {
  versions: Set<string>;
  wildcard: boolean;
}

function buildBannedMap(entries: BannedPackage[]): Map<string, BannedInfo> {
  const map = new Map<string, BannedInfo>();
  for (const { name, version } of entries) {
    if (!name) continue;
    const info = map.get(name) ?? { versions: new Set(), wildcard: false };
    const ver = version?.trim();
    if (!ver || ver === '*' || ver.toLowerCase() === 'any') {
      info.wildcard = true;
    } else {
      info.versions.add(ver);
    }
    map.set(name, info);
  }
  return map;
}

function shouldFlag(bannedInfo: BannedInfo | undefined, version: string): boolean {
  if (!bannedInfo) return false;
  if (bannedInfo.wildcard) return true;
  return bannedInfo.versions.has(version);
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

function analyzeScripts(pkgJson: any): string[] {
  const warnings: string[] = [];
  const scripts = pkgJson.scripts || {};
  const SUSPICIOUS_PATTERNS = [
    { regex: /(curl|wget)\s+/, label: 'Network request (curl/wget)' },
    { regex: /\|\s*bash/, label: 'Pipe to bash' },
    { regex: /[A-Za-z0-9+/]{60,}={0,2}/, label: 'Potential Base64 encoded string' },
    { regex: /\\x[0-9a-fA-F]{2}/, label: 'Hex escape sequence (obfuscation)' },
    { regex: /eval\s*\(/, label: 'Use of eval()' },
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
 * Scans the project for banned packages.
 * @param {string} projectRoot - The root directory of the project.
 * @param {string|Array} bannedListSource - Path to the CSV file OR an array of banned package objects.
 * @returns {Promise<{ matches: Array<{name: string, version: string, section: string}>, warnings: string[] }>}
 */
export async function scanProject(projectRoot: string, bannedListSource: string | BannedPackage[]) {
  // Input Validation: Path Traversal Protection
  const resolvedRoot = path.resolve(projectRoot);
  // Ensure resolved path is still within expected bounds if necessary, 
  // but for a CLI tool scanning a user-provided path, resolve is usually enough to handle relative paths safely.
  // We can check if it exists here.
  if (!fs.existsSync(resolvedRoot)) {
    throw new Error(`Project root does not exist: ${resolvedRoot}`);
  }

  const packageJsonPath = path.join(resolvedRoot, 'package.json');
  const allWarnings: string[] = [];

  let bannedEntries: BannedPackage[];
  if (Array.isArray(bannedListSource)) {
    bannedEntries = bannedListSource;
  } else if (typeof bannedListSource === 'string') {
    if (!fs.existsSync(bannedListSource)) {
      throw new Error(`Banned list not found at ${bannedListSource}`);
    }
    bannedEntries = loadCsv(bannedListSource);
  } else {
    throw new Error('Invalid banned list source. Must be a file path or an array.');
  }

  if (!fs.existsSync(packageJsonPath)) {
    throw new Error(`package.json not found at ${packageJsonPath}`);
  }

  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

  // Heuristic Analysis
  const scriptWarnings = analyzeScripts(packageJson);
  allWarnings.push(...scriptWarnings);

  const bannedMap = buildBannedMap(bannedEntries);
  const declaredPackages = collectPackages(packageJson);

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
    warnings: lockWarnings = [],
    success,
  } = detection.handler.loadLockPackages(detection.lockPath);

  if (lockWarnings) {
    allWarnings.push(...lockWarnings);
  }

  if (!success) {
    throw new Error('Unable to analyse the dependency lockfile.');
  }

  const matches: ScanMatch[] = [];
  const seen = new Set();

  for (const [name, info] of bannedMap.entries()) {
    const versions = lockPackages.get(name);
    if (!versions || versions.size === 0) continue;

    for (const version of versions) {
      if (!shouldFlag(info, version)) continue;
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
