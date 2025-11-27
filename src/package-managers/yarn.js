const fs = require('fs');
const path = require('path');

function detectFromPackageManagerField(fieldValue) {
  if (!fieldValue) return false;
  return fieldValue.startsWith('yarn');
}

function parseDescriptors(descriptorLine) {
  const matches = descriptorLine.match(/"([^"\\]*(?:\\.[^"\\]*)*)"/g);
  if (matches && matches.length > 0) {
    return matches.map((entry) => entry.slice(1, -1));
  }
  return descriptorLine
    .split(/,\s*/)
    .map((token) => token.trim())
    .filter(Boolean);
}

function normalizeDescriptor(descriptor) {
  if (!descriptor) return descriptor;
  let value = descriptor.trim();
  value = value.replace(/^(patch|virtual):/, '');
  value = value.replace('@npm:', '@');
  return value;
}

function extractPackageName(descriptor) {
  if (!descriptor) return null;
  const normalized = normalizeDescriptor(descriptor);

  if (normalized.startsWith('@')) {
    const secondAt = normalized.indexOf('@', 1);
    if (secondAt === -1) {
      return normalized;
    }
    return normalized.slice(0, secondAt);
  }

  const atIndex = normalized.indexOf('@');
  if (atIndex === -1) {
    return normalized;
  }
  return normalized.slice(0, atIndex);
}

function parseYarnLock(content) {
  const results = new Map();
  const lines = content.split(/\r?\n/);

  let descriptors = [];
  let version = null;

  const flush = () => {
    if (!descriptors.length) return;
    const resolvedVersion = version || 'unknown';

    for (const descriptor of descriptors) {
      const name = extractPackageName(descriptor);
      if (!name) continue;
      const set = results.get(name) ?? new Set();
      set.add(resolvedVersion);
      results.set(name, set);
    }

    descriptors = [];
    version = null;
  };

  for (const lineRaw of lines) {
    const line = lineRaw.replace(/\s+$/, '');
    const trimmed = line.trim();

    if (!trimmed) continue;

    if (!line.startsWith(' ') && line.endsWith(':')) {
      flush();
      descriptors = parseDescriptors(line.slice(0, -1));
      version = null;
      continue;
    }

    if (!descriptors.length) continue;

    if (trimmed.startsWith('version ')) {
      const match = trimmed.match(/^version\s+"([^"]+)"/);
      if (match) {
        version = match[1];
        continue;
      }
    }

    if (trimmed.startsWith('version:')) {
      const match = trimmed.match(/^version:\s*"?([^"\s]+)"?/);
      if (match) {
        version = match[1];
        continue;
      }
    }

    if (!version && trimmed.startsWith('resolution:')) {
      const match = trimmed.match(/@npm:([^"']+)/);
      if (match) {
        version = match[1];
        continue;
      }
    }
  }

  flush();
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
      warnings.push(`No packages parsed from ${path.basename(lockPath)}; unsupported format?`);
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
