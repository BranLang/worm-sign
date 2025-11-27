const fs = require('fs');
const path = require('path');
const os = require('os');

const CACHE_FILE = path.join(os.homedir(), '.worm-sign-cache.json');
const TTL_MS = 60 * 60 * 1000; // 1 hour

function loadCache() {
  if (!fs.existsSync(CACHE_FILE)) {
    return null;
  }
  try {
    const data = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    if (Date.now() - data.timestamp > TTL_MS) {
      return null;
    }
    return data.packages;
  } catch (e) {
    return null;
  }
}

function saveCache(packages) {
  try {
    const data = {
      timestamp: Date.now(),
      packages,
    };
    fs.writeFileSync(CACHE_FILE, JSON.stringify(data), 'utf8');
  } catch (e) {
    // Ignore cache write errors
  }
}

module.exports = { loadCache, saveCache };
