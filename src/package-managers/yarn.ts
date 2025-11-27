import * as fs from 'fs';
import * as path from 'path';
// @ts-ignore
import * as lockfile from '@yarnpkg/lockfile';
import { LockPackageResult, PackageManagerHandler } from '../types';

function detectFromPackageManagerField(fieldValue: string): boolean {
  if (!fieldValue) return false;
  return fieldValue.startsWith('yarn');
}

function parseYarnLock(content: string): { packages: Map<string, Set<string>>, integrity: Map<string, Map<string, string>> } {
  const packages = new Map<string, Set<string>>();
  const integrity = new Map<string, Map<string, string>>();
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
    return { packages, integrity };
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
          const set = packages.get(pkgName) ?? new Set();
          set.add(version);
          packages.set(pkgName, set);

          if (info.integrity || info.resolved) {
            // Yarn 1 often puts hash in 'resolved' if 'integrity' is missing, or 'integrity' itself.
            // We prioritize integrity, then try to extract hash from resolved url if possible (e.g. #sha1-...)
            let hash = info.integrity;
            if (!hash && info.resolved && info.resolved.includes('#')) {
              hash = info.resolved.split('#')[1];
            }

            if (hash) {
              const pkgIntegrity = integrity.get(pkgName) ?? new Map();
              pkgIntegrity.set(version, hash);
              integrity.set(pkgName, pkgIntegrity);
            }
          }
        }
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
    const result = parseYarnLock(content);
    packages = result.packages;
    if (packages.size === 0) {
      warnings.push(`No packages parsed from ${path.basename(lockPath)}; check format.`);
    }
    return { packages, packageIntegrity: result.integrity, warnings, success: true };
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
