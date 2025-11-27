const fs = require('fs');
const path = require('path');
const lockfile = require('@yarnpkg/lockfile');

function detectFromPackageManagerField(fieldValue) {
  if (!fieldValue) return false;
  return fieldValue.startsWith('yarn');
}

function parseYarnLock(content) {
  const results = new Map();
  let parsed;
  try {
    const result = lockfile.parse(content);
    if (result.type === 'success' || result.type === 'merge') {
        parsed = result.object;
    } else {
        // Handle conflict or other states if necessary, but usually object is present
        parsed = result.object;
    }
  } catch (e) {
    throw new Error(`Yarn lockfile parse error: ${e.message}`);
  }

  if (!parsed) {
    return results;
  }

  for (const [key, info] of Object.entries(parsed)) {
    // key is like "package-name@version" or "package-name@range"
    // info is { version, resolved, integrity, dependencies }
    
    // Extract name from key. 
    // Key can be multiple comma separated: "pkg@v1, pkg@v2"
    // But @yarnpkg/lockfile usually splits them or we iterate object keys.
    // Actually @yarnpkg/lockfile returns object where keys are the descriptors.
    
    // We need to extract the package name from the descriptor.
    // Descriptor: "name@range"
    
    // Helper to extract name
    const lastAt = key.lastIndexOf('@');
    if (lastAt === -1) continue;
    
    const name = key.slice(0, lastAt);
    const version = info.version;

    if (name && version) {
        // Clean up name if it has comma (shouldn't happen with parsed object keys usually being individual entries, 
        // but let's be safe if multiple patterns map to same entry)
        // Actually, lockfile.parse returns keys as they appear in file, which might be "a@^1.0.0, a@^1.1.0"
        
        const descriptors = key.split(',').map(k => k.trim());
        for (const descriptor of descriptors) {
             const lastAtDesc = descriptor.lastIndexOf('@');
             if (lastAtDesc !== -1) {
                 const pkgName = descriptor.slice(0, lastAtDesc);
                 // Handle scoped packages: @scope/pkg@1.0.0 -> lastIndexOf is at 1.0.0
                 // If it starts with @, we might have @scope/pkg@version
                 
                 // Better regex for name extraction from descriptor string "name@range"
                 // Name is everything up to the last @, unless it's the first char (scoped)
                 // Actually, standard yarn lock keys are "pkg@range".
                 
                 const set = results.get(pkgName) ?? new Set();
                 set.add(version);
                 results.set(pkgName, set);
             }
        }
    }
  }

  return results;
}

function loadLockPackages(lockPath) {
  const warnings = [];
  let packages = new Map();

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
  } catch (err) {
    warnings.push(`Unable to read ${path.basename(lockPath)}: ${err.message}`);
    return { packages, warnings, success: false };
  }
}

module.exports = {
  id: 'yarn',
  label: 'Yarn',
  lockFiles: ['yarn.lock'],
  detectFromPackageManagerField,
  findLockFile: (repoRoot) => {
    const candidate = path.join(repoRoot, 'yarn.lock');
    return fs.existsSync(candidate) ? candidate : null;
  },
  loadLockPackages,
};
