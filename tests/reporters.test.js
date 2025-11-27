const textReporter = require('../src/reporters/text');
const jsonReporter = require('../src/reporters/json');
const sarifReporter = require('../src/reporters/sarif');


// Mock chalk and boxen
const mockChalk = {
  yellow: Object.assign((s) => s, { bold: (s) => s }),
  green: Object.assign((s) => s, { bold: (s) => s }),
  red: Object.assign((s) => s, { bold: (s) => s }),
  bold: (s) => s,
  dim: (s) => s,
  cyan: (s) => s,
  grey: (s) => s
};
const mockBoxen = (s) => s;
const context = { chalk: mockChalk, boxen: mockBoxen };

describe('Reporters', () => {
  const mockMatches = [
    { name: 'bad-package', version: '1.0.0', section: 'dependencies' },
    { name: 'worse-package', version: '2.0.0', section: 'devDependencies' },
  ];
  const mockWarnings = ['Suspicious script detected'];
  const projectRoot = '/tmp/test';

  describe('JSON Reporter', () => {
    it('should output valid JSON', () => {
      const output = jsonReporter.report(mockMatches, mockWarnings, projectRoot, context);
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
      expect(output).toContain('No banned packages found');
    });
  });

  describe('SARIF Reporter', () => {
    it('should output valid SARIF JSON', () => {
      const output = sarifReporter.report(mockMatches, mockWarnings, projectRoot, context);
      const parsed = JSON.parse(output);
      expect(parsed.runs[0].tool.driver.name).toBe('worm-sign');
      expect(parsed.runs[0].results).toHaveLength(3); // 2 matches + 1 warning
    });
  });
});
