import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { LockPackageResult, PackageManagerHandler } from '../types';

function detectFromPackageManagerField(fieldValue: string): boolean {
  if (!fieldValue) return false;
  return fieldValue.startsWith('pnpm');
}

function cleanupVersion(raw: string): string {
  if (!raw) return 'unknown';
  return raw.split('_')[0].split('(')[0].trim();
}

interface PnpmLockPackage {
  resolution?: {
    integrity?: string;
  };
  dependencies?: Record<string, string>;
}

interface PnpmLockFile {
  packages?: Record<string, PnpmLockPackage>;
}

function parsePnpmLock(content: string): {
  packages: Map<string, Set<string>>;
  integrity: Map<string, Map<string, string>>;
} {
  const packages = new Map<string, Set<string>>();
  const integrity = new Map<string, Map<string, string>>();
  let parsed: PnpmLockFile | undefined;
  try {
    parsed = yaml.load(content) as PnpmLockFile;
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`YAML parse error: ${msg}`);
  }

  if (!parsed || !parsed.packages) {
    return { packages, integrity };
  }

  for (const [key, info] of Object.entries(parsed.packages) as [string, PnpmLockPackage][]) {
    let name: string, version: string;

    const cleanKey = key.startsWith('/') ? key.slice(1) : key;

    const lastSlash = cleanKey.lastIndexOf('/');
    if (lastSlash === -1) {
      name = cleanKey;
      version = 'unknown';
    } else {
      name = cleanKey.slice(0, lastSlash);
      version = cleanupVersion(cleanKey.slice(lastSlash + 1));
    }

    if (name && version) {
      const set = packages.get(name) ?? new Set();
      set.add(version);
      packages.set(name, set);

      if (info.resolution && info.resolution.integrity) {
        const pkgIntegrity = integrity.get(name) ?? new Map();
        pkgIntegrity.set(version, info.resolution.integrity);
        integrity.set(name, pkgIntegrity);
      }
    }
  }

  return { packages, integrity };
}

function loadLockPackages(lockPath: string): LockPackageResult {
  const warnings: string[] = [];
  let packages = new Map<string, Set<string>>();

  if (!fs.existsSync(lockPath)) {
    warnings.push(`Lockfile not found at ${lockPath}`);
    return { packages, warnings, success: false };
  }

  try {
    const content = fs.readFileSync(lockPath, 'utf8');
    const result = parsePnpmLock(content);
    packages = result.packages;
    if (packages.size === 0) {
      warnings.push(`No packages parsed from ${path.basename(lockPath)}; check format.`);
    }
    return { packages, packageIntegrity: result.integrity, warnings, success: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    warnings.push(`Unable to read ${path.basename(lockPath)}: ${msg}`);
    return { packages, warnings, success: false };
  }
}

const pnpmHandler: PackageManagerHandler = {
  id: 'pnpm',
  label: 'pnpm',
  lockFiles: ['pnpm-lock.yaml'],
  detectFromPackageManagerField,
  findLockFile: (repoRoot: string) => {
    const candidate = path.join(repoRoot, 'pnpm-lock.yaml');
    return fs.existsSync(candidate) ? candidate : null;
  },
  loadLockPackages,
};

export default pnpmHandler;
