const chalk = require('chalk');

const levels = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
};

let currentLevel = levels.INFO;

function setLevel(level) {
  if (typeof level === 'string') {
    currentLevel = levels[level.toUpperCase()] ?? levels.INFO;
  } else {
    currentLevel = level;
  }
}

function debug(msg) {
  if (currentLevel <= levels.DEBUG) {
    console.log(chalk.gray(`[DEBUG] ${msg}`));
  }
}

function info(msg) {
  if (currentLevel <= levels.INFO) {
    console.log(chalk.blue(`[INFO] ${msg}`));
  }
}

function warn(msg) {
  if (currentLevel <= levels.WARN) {
    console.warn(chalk.yellow(`[WARN] ${msg}`));
  }
}

function error(msg) {
  if (currentLevel <= levels.ERROR) {
    console.error(chalk.red(`[ERROR] ${msg}`));
  }
}

module.exports = {
  setLevel,
  debug,
  info,
  warn,
  error,
  levels,
};
