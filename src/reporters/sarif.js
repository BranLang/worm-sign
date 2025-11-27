const { generateSarif } = require('../formatters/sarif');

function report(matches, warnings, projectRoot) {
  const sarif = generateSarif(matches, warnings, projectRoot);
  return JSON.stringify(sarif, null, 2);
}

module.exports = { report };
