import { generateSarif } from '../formatters/sarif';
import { ScanMatch } from '../types';

export function report(matches: ScanMatch[], warnings: string[], projectRoot: string) {
  const sarif = generateSarif(matches, warnings, projectRoot);
  return JSON.stringify(sarif, null, 2);
}
