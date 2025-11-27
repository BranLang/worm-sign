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

function parsePnpmLock(content: string): Map<string, Set<string>> {
  const results = new Map<string, Set<string>>();
  let parsed: any;
  try {
    parsed = yaml.load(content);
  } catch (e: any) {
    throw new Error(`YAML parse error: ${e.message}`);
  }

  if (!parsed || !parsed.packages) {
    return results;
  }

  for (const key of Object.keys(parsed.packages)) {
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
      const set = results.get(name) ?? new Set();
      set.add(version);
      results.set(name, set);
    }
  }

  return results;
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
    packages = parsePnpmLock(content);
    if (packages.size === 0) {
      warnings.push(`No packages parsed from ${path.basename(lockPath)}; check format.`);
    }
    return { packages, warnings, success: true };
  } catch (err: any) {
    warnings.push(`Unable to read ${path.basename(lockPath)}: ${err.message}`);
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
