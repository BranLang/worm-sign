const Table = require('cli-table3');

function report(matches, warnings, projectRoot, context = {}) {
  const { chalk, boxen } = context;
  
  // Fallback mocks if not provided (e.g. in tests if not mocked explicitly, though tests should provide them)
  const c = chalk || { 
      yellow: { bold: (s) => s }, 
      green: { bold: (s) => s }, 
      red: { bold: (s) => s }, 
      bold: (s) => s, 
      dim: (s) => s,
      yellow: (s) => s,
      red: (s) => s,
      cyan: (s) => s,
      grey: (s) => s
  };
  const b = boxen || ((s) => s);

  let output = '';

  if (warnings.length > 0) {
    output += '\n' + c.yellow.bold('⚠️  Warnings:') + '\n';
    warnings.forEach((msg) => {
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

module.exports = { report };
