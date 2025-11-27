const fs = require('fs');
const path = require('path');
const https = require('https');

const packageManagers = [
  require('./package-managers/pnpm'),
  require('./package-managers/yarn'),
  require('./package-managers/npm'),
];

function loadCsv(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  return parseCsv(raw);
}

function parseCsv(raw) {
  return raw
    .split(/\r?\n/)
    .slice(1)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => {
      const [name, version] = line.split(',').map((segment) => segment?.trim());
      return { name, version: version || '' };
    })
    .filter(({ name }) => !!name);
}

const SOURCES = {
  ibm: {
    url: 'https://datalake-rest-api.cio-devex-data-lake.dal.app.cirrus.ibm.com/v1/ciso/vulnerable-packages',
    type: 'json',
  },
  koi: {
    url: 'https://docs.google.com/spreadsheets/d/16aw6s7mWoGU7vxBciTEZSaR5HaohlBTfVirvI-PypJc/export?format=csv&gid=1289659284',
    type: 'csv',
  },
};


function fetchFromApi(sourceConfig) {
  const { url, type } = sourceConfig;
  if (!url || !type) {
    return Promise.reject(new Error('Invalid source configuration: missing url or type'));
  }

  const fetchUrl = (targetUrl, attempt = 1) => {
      return new Promise((resolve, reject) => {
        if (attempt > 5) {
            reject(new Error('Too many redirects'));
            return;
        }
        const req = https.get(targetUrl, { headers: { 'Accept': type === 'json' ? 'application/json' : 'text/csv' } }, (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
              // Follow redirect
              fetchUrl(res.headers.location, attempt + 1).then(resolve).catch(reject);
              return;
          }
          if (res.statusCode !== 200) {
            reject(new Error(`API request failed with status ${res.statusCode}`));
            return;
          }
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try {
              if (type === 'json') {
                const json = JSON.parse(data);
                if (!Array.isArray(json.packages)) {
                   reject(new Error('Invalid API response: "packages" field must be an array.'));
                   return;
                }
                resolve(json.packages);
              } else if (type === 'csv') {
                const lines = data.split(/\r?\n/);
                const packages = [];
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed || trimmed.startsWith('#') || trimmed.toLowerCase().startsWith('package') || trimmed.toLowerCase().startsWith('name')) continue;
                    const parts = trimmed.split(',');
                    if (parts.length >= 2) {
                        packages.push({
                            name: parts[0].trim(),
                            version: parts[1].trim(),
                            reason: 'Banned by Koi Security Feed'
                        });
                    }
                }
                resolve(packages);
              }
            } catch (e) {
              reject(new Error(`Failed to parse API response: ${e.message}`));
            }
          });
        });
        
        req.on('error', reject);
        req.setTimeout(5000, () => {
            req.destroy();
            reject(new Error('API request timed out after 5000ms'));
        });
      });
  };

  return fetchUrl(url);
}

function collectPackages(pkgJson) {
  const sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];

  const results = new Map();

  for (const section of sections) {
    const entries = pkgJson[section];
    if (!entries) continue;
    for (const [name, version] of Object.entries(entries)) {
      results.set(name, { section, version });
    }
  }

  return results;
}

function buildBannedMap(entries) {
  const map = new Map();
  for (const { name, version } of entries) {
    if (!name) continue;
    const info = map.get(name) ?? { versions: new Set(), wildcard: false };
    const ver = version?.trim();
    if (!ver || ver === '*' || ver.toLowerCase() === 'any') {
      info.wildcard = true;
    } else {
      info.versions.add(ver);
    }
    map.set(name, info);
  }
  return map;
}

function shouldFlag(bannedInfo, version) {
  if (!bannedInfo) return false;
  if (bannedInfo.wildcard) return true;
  return bannedInfo.versions.has(version);
}

function findLockForHandler(projectRoot, handler) {
  if (typeof handler.findLockFile === 'function') {
    const resolved = handler.findLockFile(projectRoot);
    if (resolved) return resolved;
  }

  if (Array.isArray(handler.lockFiles)) {
    for (const fileName of handler.lockFiles) {
      const candidate = path.join(projectRoot, fileName);
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
  }

  return null;
}

function detectPackageManager(projectRoot, packageJson) {
  const warnings = [];
  const packageManagerField = packageJson?.packageManager;
  let preferred = null;

  if (packageManagerField) {
    preferred =
      packageManagers.find(
        (handler) =>
          typeof handler.detectFromPackageManagerField === 'function' &&
          handler.detectFromPackageManagerField(packageManagerField),
      ) || null;
  }

  const available = packageManagers
    .map((handler) => ({ handler, lockPath: findLockForHandler(projectRoot, handler) }))
    .filter((entry) => !!entry.lockPath);

  if (preferred) {
    const preferredLockPath = findLockForHandler(projectRoot, preferred);
    if (preferredLockPath) {
      return { handler: preferred, lockPath: preferredLockPath, warnings };
    }

    if (available.length > 0) {
      const fallback = available[0];
      warnings.push(
        `package.json declares ${preferred.label ?? preferred.id}, but its lockfile is missing; falling back to ${fallback.handler.label ?? fallback.handler.id}.`,
      );
      return { handler: fallback.handler, lockPath: fallback.lockPath, warnings };
    }

    warnings.push(
      `package.json declares ${preferred.label ?? preferred.id}, but no matching lockfile was found.`,
    );
    return { handler: preferred, lockPath: null, warnings };
  }

  if (available.length === 1) {
    return { handler: available[0].handler, lockPath: available[0].lockPath, warnings };
  }

  if (available.length > 1) {
    const names = available.map((entry) => entry.handler.label ?? entry.handler.id).join(', ');
    warnings.push(
      `Multiple lockfiles detected (${names}); defaulting to ${available[0].handler.label ?? available[0].handler.id}.`,
    );
    return { handler: available[0].handler, lockPath: available[0].lockPath, warnings };
  }

  return { handler: null, lockPath: null, warnings };
}

function analyzeScripts(pkgJson) {
  const warnings = [];
  const scripts = pkgJson.scripts || {};
  const SUSPICIOUS_PATTERNS = [
    { regex: /(curl|wget)\s+/, label: 'Network request (curl/wget)' },
    { regex: /\|\s*bash/, label: 'Pipe to bash' },
    { regex: /[A-Za-z0-9+/]{60,}={0,2}/, label: 'Potential Base64 encoded string' },
    { regex: /\\x[0-9a-fA-F]{2}/, label: 'Hex escape sequence (obfuscation)' },
    { regex: /eval\s*\(/, label: 'Use of eval()' },
  ];

  for (const [name, script] of Object.entries(scripts)) {
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.regex.test(script)) {
        warnings.push(`Suspicious script detected in '${name}': ${pattern.label}`);
      }
    }
  }
  return warnings;
}

/**
 * Scans the project for banned packages.
 * @param {string} projectRoot - The root directory of the project.
 * @param {string|Array} bannedListSource - Path to the CSV file OR an array of banned package objects.
 * @returns {Promise<{ matches: Array<{name: string, version: string, section: string}>, warnings: string[] }>}
 */
async function scanProject(projectRoot, bannedListSource) {
  const packageJsonPath = path.join(projectRoot, 'package.json');
  const allWarnings = [];

  let bannedEntries;
  if (Array.isArray(bannedListSource)) {
    bannedEntries = bannedListSource;
  } else if (typeof bannedListSource === 'string') {
    if (!fs.existsSync(bannedListSource)) {
      throw new Error(`Banned list not found at ${bannedListSource}`);
    }
    bannedEntries = loadCsv(bannedListSource);
  } else {
    throw new Error('Invalid banned list source. Must be a file path or an array.');
  }

  if (!fs.existsSync(packageJsonPath)) {
    throw new Error(`package.json not found at ${packageJsonPath}`);
  }

  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  
  // Heuristic Analysis
  const scriptWarnings = analyzeScripts(packageJson);
  allWarnings.push(...scriptWarnings);

  const bannedMap = buildBannedMap(bannedEntries);
  const declaredPackages = collectPackages(packageJson);

  const detection = detectPackageManager(projectRoot, packageJson);
  if (detection.warnings) {
    allWarnings.push(...detection.warnings);
  }

  if (!detection.handler) {
    throw new Error(
      'Unable to determine which package manager to inspect. Add a lockfile or set the packageManager field in package.json.',
    );
  }

  if (!detection.lockPath) {
    throw new Error(
      `Detected ${detection.handler.label ?? detection.handler.id}, but no lockfile was found. Please generate a lockfile and retry.`,
    );
  }

  const {
    packages: lockPackages = new Map(),
    warnings: lockWarnings = [],
    success,
  } = detection.handler.loadLockPackages(detection.lockPath);

  if (lockWarnings) {
    allWarnings.push(...lockWarnings);
  }

  if (!success) {
    throw new Error('Unable to analyse the dependency lockfile.');
  }

  const matches = [];
  const seen = new Set();

  for (const [name, info] of bannedMap.entries()) {
    const versions = lockPackages.get(name);
    if (!versions || versions.size === 0) continue;

    for (const version of versions) {
      if (!shouldFlag(info, version)) continue;
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const declared = declaredPackages.get(name);
      const section = declared ? declared.section : 'transitive';
      matches.push({ name, version, section });
    }
  }

  return { matches, warnings: allWarnings };
}

module.exports = {
  scanProject,
  loadCsv,
  fetchFromApi,
  SOURCES,
};
