const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

function detectFromPackageManagerField(fieldValue) {
  if (!fieldValue) return false;
  return fieldValue.startsWith('pnpm');
}

function cleanupVersion(raw) {
  if (!raw) return 'unknown';
  // pnpm versions often look like "1.2.3(peer...)" or "1.2.3_..."
  return raw.split('_')[0].split('(')[0].trim();
}

function parsePnpmLock(content) {
  const results = new Map();
  let parsed;
  try {
    parsed = yaml.load(content);
  } catch (e) {
    throw new Error(`YAML parse error: ${e.message}`);
  }

  if (!parsed || !parsed.packages) {
    return results;
  }

  for (const [key, details] of Object.entries(parsed.packages)) {
    // key is usually "/name/version" or "/name/version(...)"
    // details has resolution: { integrity } and dependencies/optionalDependencies
    
    // We need to extract name and version from the key
    // Key format: /<pkg-name>/<version>
    // Example: /@babel/core/7.12.3
    
    let name, version;
    
    // Remove leading slash
    const cleanKey = key.startsWith('/') ? key.slice(1) : key;
    
    // Split by last slash to separate name and version
    const lastSlash = cleanKey.lastIndexOf('/');
    if (lastSlash === -1) {
        // Fallback or weird format
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

function loadLockPackages(lockPath) {
  const warnings = [];
  let packages = new Map();

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
  } catch (err) {
    warnings.push(`Unable to read ${path.basename(lockPath)}: ${err.message}`);
    return { packages, warnings, success: false };
  }
}

module.exports = {
  id: 'pnpm',
  label: 'pnpm',
  lockFiles: ['pnpm-lock.yaml'],
  detectFromPackageManagerField,
  findLockFile: (repoRoot) => {
    const candidate = path.join(repoRoot, 'pnpm-lock.yaml');
    return fs.existsSync(candidate) ? candidate : null;
  },
  loadLockPackages,
};
