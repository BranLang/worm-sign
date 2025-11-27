function report(matches, warnings, projectRoot) {
  return JSON.stringify({ matches, warnings, projectRoot }, null, 2);
}

module.exports = { report };
