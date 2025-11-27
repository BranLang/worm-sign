import { generateSarif } from '../formatters/sarif';
import { ScanMatch } from '../types';

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function report(matches: ScanMatch[], warnings: string[], _projectRoot: string) {
  const sarif = generateSarif(matches, warnings);
  return JSON.stringify(sarif, null, 2);
}
