// @ts-ignore
import Table = require('cli-table3');
import { ScanMatch } from '../types';

export function report(matches: ScanMatch[], warnings: string[], projectRoot: string, context: any = {}) {
  const { chalk, boxen } = context;

  // Fallback mocks if not provided
  const c = chalk || {
    yellow: { bold: (s: string) => s },
    green: { bold: (s: string) => s },
    red: { bold: (s: string) => s },
    bold: (s: string) => s,
    dim: (s: string) => s,
    cyan: (s: string) => s,
    grey: (s: string) => s
  };
  // Handle simple color functions if they are not objects


  const b = boxen || ((s: string) => s);

  let output = '';

  if (warnings.length > 0) {
    output += '\n' + c.yellow.bold('⚠️  Warnings:') + '\n';
    warnings.forEach((msg: string) => {
      output += c.yellow(`  - ${msg}`) + '\n';
    });
  }

  if (matches.length === 0) {
    output += '\n' + b(c.green.bold('✅ No banned packages found.\nThe spice must flow.'), { padding: 1, borderStyle: 'round', borderColor: 'green' }) + '\n';
    return output;
  }

  output += '\n' + b(c.red.bold('🚫 Banned packages detected!'), { padding: 1, borderStyle: 'double', borderColor: 'red' }) + '\n\n';

  const table = new Table({
    head: [c.bold('Package'), c.bold('Version'), c.bold('Location')],
    style: {
      head: [], // We handle colors manually
      border: [],
    },
  });

  matches.forEach(({ name, version, section }) => {
    table.push([
      c.red.bold(name),
      c.red(version),
      c.dim(section),
    ]);
  });

  output += table.toString() + '\n';

  return output;
}
