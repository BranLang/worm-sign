const fs = require('fs');
const path = require('path');

function detectFromPackageManagerField(fieldValue) {
  if (!fieldValue) return false;
  return fieldValue.startsWith('pnpm');
}

function cleanupVersion(raw) {
  if (!raw) return 'unknown';
  return raw.split('_')[0].split('(')[0].trim();
}

function normalizeName(raw) {
  if (!raw) return raw;
  let name = raw;

  if (name.includes('node_modules/')) {
    name = name.slice(name.lastIndexOf('node_modules/') + 'node_modules/'.length);
  }

  if (name.includes('registry.npmjs.org/')) {
    name = name.slice(name.lastIndexOf('registry.npmjs.org/') + 'registry.npmjs.org/'.length);
  }

  const segments = name.split('/').filter(Boolean);
  if (segments.length === 0) return null;

  if (segments[0].startsWith('@')) {
    if (segments.length >= 2) {
      return `${segments[0]}/${segments[1]}`;
    }
    return segments[0];
  }

  return segments[segments.length - 1];
}

function parsePackageKey(key) {
  const stripped = key
    .replace(/^['"]|['"]$/g, '')
    .replace(/:$/, '')
    .trim();
  const withoutPrefix = stripped.startsWith('/') ? stripped.slice(1) : stripped;
  const primary = withoutPrefix.split('(')[0];

  const atIndex = primary.lastIndexOf('@');
  if (atIndex > 0) {
    const namePart = primary.slice(0, atIndex);
    const versionPart = primary.slice(atIndex + 1);
    return {
      name: normalizeName(namePart),
      version: cleanupVersion(versionPart),
    };
  }

  const segments = primary.split('/');
  if (segments.length >= 2) {
    const versionPart = segments.pop();
    const namePart = segments.join('/');
    return {
      name: normalizeName(namePart),
      version: cleanupVersion(versionPart),
    };
  }

  return { name: normalizeName(primary), version: 'unknown' };
}

function parsePnpmLock(content) {
  const results = new Map();
  const lines = content.split(/\r?\n/);

  let inPackages = false;
  let current = null;

  const flush = () => {
    if (!current || !current.name) {
      current = null;
      return;
    }
    const version = current.version || current.versionFromKey || 'unknown';
    const set = results.get(current.name) ?? new Set();
    set.add(version);
    results.set(current.name, set);
    current = null;
  };

  for (const rawLine of lines) {
    const line = rawLine.replace(/\s+$/, '');
    const trimmed = line.trim();

    if (!inPackages) {
      if (trimmed === 'packages:' || trimmed.startsWith('packages:')) {
        inPackages = true;
      }
      continue;
    }

    if (!line.startsWith(' ')) {
      flush();
      if (trimmed === '') continue;
      break;
    }

    if (!trimmed) continue;

    const isPackageKey = line.startsWith('  ') && !line.startsWith('    ') && trimmed.endsWith(':');
    if (isPackageKey) {
      flush();
      const parsed = parsePackageKey(trimmed);
      current = {
        name: parsed.name,
        versionFromKey: parsed.version,
        version: null,
      };
      continue;
    }

    if (!current) continue;

    if (trimmed.startsWith('version:')) {
      const match = trimmed.match(/^version:\s*['"]?([^'"\s]+)['"]?/);
      if (match) {
        current.version = cleanupVersion(match[1]);
      }
      continue;
    }

    if (!current.version && trimmed.startsWith('resolution:')) {
      const match = trimmed.match(/version[:=]\s*['"]?([^'"\s]+)['"]?/);
      if (match) {
        current.version = cleanupVersion(match[1]);
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
    packages = parsePnpmLock(content);
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
