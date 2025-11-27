import * as fs from 'fs';
import * as path from 'path';
// @ts-ignore
import * as lockfile from '@yarnpkg/lockfile';
import { LockPackageResult, PackageManagerHandler } from '../types';

function detectFromPackageManagerField(fieldValue: string): boolean {
  if (!fieldValue) return false;
  return fieldValue.startsWith('yarn');
}

function parseYarnLock(content: string): Map<string, Set<string>> {
  const results = new Map<string, Set<string>>();
  let parsed: any;
  try {
    const result = lockfile.parse(content);
    if (result.type === 'success' || result.type === 'merge') {
      parsed = result.object;
    } else {
      parsed = result.object;
    }
  } catch (e: any) {
    throw new Error(`Yarn lockfile parse error: ${e.message}`);
  }

  if (!parsed) {
    return results;
  }

  for (const [key, info] of Object.entries(parsed) as [string, any][]) {
    const lastAt = key.lastIndexOf('@');
    if (lastAt === -1) continue;

    const name = key.slice(0, lastAt);
    const version = info.version;

    if (name && version) {
      const descriptors = key.split(',').map(k => k.trim());
      for (const descriptor of descriptors) {
        const lastAtDesc = descriptor.lastIndexOf('@');
        if (lastAtDesc !== -1) {
          const pkgName = descriptor.slice(0, lastAtDesc);
          const set = results.get(pkgName) ?? new Set();
          set.add(version);
          results.set(pkgName, set);
        }
      }
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
    packages = parseYarnLock(content);
    if (packages.size === 0) {
      warnings.push(`No packages parsed from ${path.basename(lockPath)}; check format.`);
    }
    return { packages, warnings, success: true };
  } catch (err: any) {
    warnings.push(`Unable to read ${path.basename(lockPath)}: ${err.message}`);
    return { packages, warnings, success: false };
  }
}

const yarnHandler: PackageManagerHandler = {
  id: 'yarn',
  label: 'Yarn',
  lockFiles: ['yarn.lock'],
  detectFromPackageManagerField,
  findLockFile: (repoRoot: string) => {
    const candidate = path.join(repoRoot, 'yarn.lock');
    return fs.existsSync(candidate) ? candidate : null;
  },
  loadLockPackages,
};

export default yarnHandler;
