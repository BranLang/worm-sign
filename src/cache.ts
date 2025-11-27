import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { BannedPackage } from './types';

const CACHE_FILE = path.join(os.homedir(), '.worm-sign-cache.json');
const TTL_MS = 60 * 60 * 1000; // 1 hour

interface CacheData {
  timestamp: number;
  packages: BannedPackage[];
}

export function loadCache(): BannedPackage[] | null {
  if (!fs.existsSync(CACHE_FILE)) {
    return null;
  }
  try {
    const data = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8')) as CacheData;
    if (Date.now() - data.timestamp > TTL_MS) {
      return null;
    }
    return data.packages;
  } catch (e) {
    return null;
  }
}

export function saveCache(packages: BannedPackage[]): void {
  try {
    const data: CacheData = {
      timestamp: Date.now(),
      packages,
    };
    fs.writeFileSync(CACHE_FILE, JSON.stringify(data), 'utf8');
  } catch (e) {
    // Ignore cache write errors
  }
}
