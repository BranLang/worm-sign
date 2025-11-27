const fs = require('fs');
const path = require('path');

function collectFromLock(lockJson) {
  const results = new Map();

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

function traverseDeps(deps, results) {
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

function inferNameFromPath(pkgPath) {
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

function detectFromPackageManagerField(fieldValue) {
  if (!fieldValue) return false;
  return fieldValue.startsWith('npm');
}

function findLockFile(repoRoot, lockFiles) {
  for (const fileName of lockFiles) {
    const fullPath = path.join(repoRoot, fileName);
    if (fs.existsSync(fullPath)) {
      return fullPath;
    }
  }
  return null;
}

function loadLockPackages(lockPath) {
  const warnings = [];
  let packages = new Map();

  if (!fs.existsSync(lockPath)) {
    warnings.push(`Lockfile not found at ${lockPath}`);
    return { packages, warnings, success: false };
  }

  try {
    const lockJson = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    packages = collectFromLock(lockJson);
    return { packages, warnings, success: true };
  } catch (err) {
    warnings.push(`Unable to parse ${path.basename(lockPath)}: ${err.message}`);
    return { packages, warnings, success: false };
  }
}

module.exports = {
  id: 'npm',
  label: 'npm',
  lockFiles: ['package-lock.json', 'npm-shrinkwrap.json'],
  detectFromPackageManagerField,
  findLockFile: (repoRoot) => findLockFile(repoRoot, ['package-lock.json', 'npm-shrinkwrap.json']),
  loadLockPackages,
};
