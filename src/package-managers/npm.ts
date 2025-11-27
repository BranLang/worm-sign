import * as fs from 'fs';
import * as path from 'path';
import { LockPackageResult, PackageManagerHandler } from '../types';

interface NpmLockPackage {
  name?: string;
  version?: string;
  resolved?: string;
  dependencies?: Record<string, NpmLockPackage>;
  requires?: Record<string, NpmLockPackage>;
}

interface NpmLockFile {
  packages?: Record<string, NpmLockPackage>;
  dependencies?: Record<string, NpmLockPackage>;
}

function collectFromLock(lockJson: NpmLockFile): Map<string, Set<string>> {
  const results = new Map<string, Set<string>>();

  if (lockJson.packages) {
    for (const [pkgPath, info] of Object.entries(lockJson.packages)) {
      if (!info) continue;
      const name = info.name || inferNameFromPath(pkgPath);
      if (!name) continue;
      const set = results.get(name) ?? new Set();
      set.add(info.version || info.resolved || 'unknown');
      results.set(name, set);
    }
  }

  if (lockJson.dependencies) {
    traverseDeps(lockJson.dependencies, results);
  }

  return results;
}

function traverseDeps(deps: Record<string, NpmLockPackage>, results: Map<string, Set<string>>) {
  if (!deps) return;
  for (const [name, info] of Object.entries(deps)) {
    const set = results.get(name) ?? new Set();
    set.add(info?.version || 'unknown');
    results.set(name, set);
    if (info?.dependencies) {
      traverseDeps(info.dependencies, results);
    }
    if (info?.requires) {
      traverseDeps(info.requires, results);
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
  let packages = new Map<string, Set<string>>();

  if (!fs.existsSync(lockPath)) {
    warnings.push(`Lockfile not found at ${lockPath}`);
    return { packages, warnings, success: false };
  }

  try {
    const lockJson = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    packages = collectFromLock(lockJson);
    return { packages, warnings, success: true };
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
  findLockFile: (repoRoot: string) => findLockFile(repoRoot, ['package-lock.json', 'npm-shrinkwrap.json']),
  loadLockPackages,
};

export default npmHandler;
