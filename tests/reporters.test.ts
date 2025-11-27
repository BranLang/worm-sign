import * as textReporter from '../src/reporters/text';
import * as jsonReporter from '../src/reporters/json';
import * as sarifReporter from '../src/reporters/sarif';
import { ScanMatch } from '../src/types';

// Mock chalk and boxen
const mockChalk: any = {
  yellow: Object.assign((s: string) => s, { bold: (s: string) => s }),
  green: Object.assign((s: string) => s, { bold: (s: string) => s }),
  red: Object.assign((s: string) => s, { bold: (s: string) => s }),
  bold: (s: string) => s,
  dim: (s: string) => s,
  cyan: (s: string) => s,
  grey: (s: string) => s
};
const mockBoxen = (s: string) => s;
const context = { chalk: mockChalk, boxen: mockBoxen };

describe('Reporters', () => {
  const mockMatches: ScanMatch[] = [
    { name: 'bad-package', version: '1.0.0', section: 'dependencies' },
    { name: 'worse-package', version: '2.0.0', section: 'devDependencies' },
  ];
  const mockWarnings = ['Suspicious script detected'];
  const projectRoot = '/tmp/test';

  describe('JSON Reporter', () => {
    it('should output valid JSON', () => {
      const output = jsonReporter.report(mockMatches, mockWarnings, projectRoot);
      const parsed = JSON.parse(output);
      expect(parsed).toEqual({
        matches: mockMatches,
        warnings: mockWarnings,
        projectRoot,
      });
    });
  });

  describe('Text Reporter', () => {
    it('should contain package names', () => {
      const output = textReporter.report(mockMatches, mockWarnings, projectRoot, context);
      expect(output).toContain('bad-package');
      expect(output).toContain('worse-package');
    });

    it('should contain warnings', () => {
      const output = textReporter.report(mockMatches, mockWarnings, projectRoot, context);
      expect(output).toContain('Suspicious script detected');
    });

    it('should show success message when no matches', () => {
      const output = textReporter.report([], [], projectRoot, context);
      expect(output).toContain('No wormsign detected');
    });
  });

  describe('SARIF Reporter', () => {
    it('should output valid SARIF JSON', () => {
      const output = sarifReporter.report(mockMatches, mockWarnings, projectRoot);
      const parsed = JSON.parse(output);
      expect(parsed.runs[0].tool.driver.name).toBe('worm-sign');
      expect(parsed.runs[0].results).toHaveLength(3); // 2 matches + 1 warning
    });
  });
});
