import { ScanMatch } from '../types';

export function report(matches: ScanMatch[], warnings: string[], projectRoot: string) {
  return JSON.stringify({ matches, warnings, projectRoot }, null, 2);
}
