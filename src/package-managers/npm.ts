import * as fs from 'fs';
import * as path from 'path';
import { LockPackageResult, PackageManagerHandler } from '../types';

interface NpmLockPackage {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, NpmLockPackage>;
  requires?: Record<string, NpmLockPackage>;
}

interface NpmLockFile {
  packages?: Record<string, NpmLockPackage>;
  dependencies?: Record<string, NpmLockPackage>;
}

function collectFromLock(lockJson: NpmLockFile): {
  packages: Map<string, Set<string>>;
  integrity: Map<string, Map<string, string>>;
} {
  const packages = new Map<string, Set<string>>();
  const integrity = new Map<string, Map<string, string>>();

  if (lockJson.packages) {
    for (const [pkgPath, info] of Object.entries(lockJson.packages)) {
      if (!info) continue;
      const name = info.name || inferNameFromPath(pkgPath);
      if (!name) continue;

      const set = packages.get(name) ?? new Set();
      const ver = info.version || info.resolved || 'unknown';
      set.add(ver);
      packages.set(name, set);

      if (info.integrity) {
        const pkgIntegrity = integrity.get(name) ?? new Map();
        pkgIntegrity.set(ver, info.integrity);
        integrity.set(name, pkgIntegrity);
      }
    }
  }

  if (lockJson.dependencies) {
    traverseDeps(lockJson.dependencies, packages, integrity);
  }

  return { packages, integrity };
}

function traverseDeps(
  deps: Record<string, NpmLockPackage>,
  packages: Map<string, Set<string>>,
  integrity: Map<string, Map<string, string>>,
) {
  if (!deps) return;
  for (const [name, info] of Object.entries(deps)) {
    const set = packages.get(name) ?? new Set();
    const ver = info?.version || 'unknown';
    set.add(ver);
    packages.set(name, set);

    if (info?.integrity) {
      const pkgIntegrity = integrity.get(name) ?? new Map();
      pkgIntegrity.set(ver, info.integrity);
      integrity.set(name, pkgIntegrity);
    }

    if (info?.dependencies) {
      traverseDeps(info.dependencies, packages, integrity);
    }
    if (info?.requires) {
      traverseDeps(info.requires, packages, integrity);
    }
  }
}

function inferNameFromPath(pkgPath: string): string | null {
  if (!pkgPath || pkgPath === '') return null;
  const segments = pkgPath.split('node_modules/').filter(Boolean);
  if (segments.length === 0) return null;
  const lastSegment = segments[segments.length - 1];
  if (lastSegment.startsWith('@')) {
    const scoped = segments.slice(-2).join('/');
    return scoped || lastSegment;
  }
  return lastSegment;
}

function detectFromPackageManagerField(fieldValue: string): boolean {
  if (!fieldValue) return false;
  return fieldValue.startsWith('npm');
}

function findLockFile(repoRoot: string, lockFiles: string[]): string | null {
  for (const fileName of lockFiles) {
    const fullPath = path.join(repoRoot, fileName);
    if (fs.existsSync(fullPath)) {
      return fullPath;
    }
  }
  return null;
}

function loadLockPackages(lockPath: string): LockPackageResult {
  const warnings: string[] = [];
  const packages = new Map<string, Set<string>>();

  if (!fs.existsSync(lockPath)) {
    warnings.push(`Lockfile not found at ${lockPath}`);
    return { packages, warnings, success: false };
  }

  try {
    const lockJson = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    const result = collectFromLock(lockJson);
    return {
      packages: result.packages,
      packageIntegrity: result.integrity,
      warnings,
      success: true,
    };
  } catch (err: any) {
    warnings.push(`Unable to parse ${path.basename(lockPath)}: ${err.message}`);
    return { packages, warnings, success: false };
  }
}

const npmHandler: PackageManagerHandler = {
  id: 'npm',
  label: 'npm',
  lockFiles: ['package-lock.json', 'npm-shrinkwrap.json'],
  detectFromPackageManagerField,
  findLockFile: (repoRoot: string) =>
    findLockFile(repoRoot, ['package-lock.json', 'npm-shrinkwrap.json']),
  loadLockPackages,
};

export default npmHandler;
