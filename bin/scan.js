#!/usr/bin/env node

const path = require('path');
const { program } = require('commander');
const { scanProject, fetchFromApi } = require('../src/index');
const { version } = require('../package.json');

const scriptDir = __dirname;
// Default to the bundled list in the package
const defaultDataDir = path.resolve(scriptDir, '..');

function resolveProjectRoot(override) {
  return override
    ? path.resolve(override)
    : process.env.PKG_SCAN_ROOT
      ? path.resolve(process.env.PKG_SCAN_ROOT)
      : process.cwd();
}

function resolveDataDir() {
  const override = process.env.PKG_SCAN_DATA_ROOT;
  return override ? path.resolve(override) : defaultDataDir;
}

program
  .name('worm-sign')
  .description('Scan your project for packages compromised by the Shai Hulud malware.')
  .version(version)
  .option('-f, --fetch', 'Fetch the latest banned packages from the API')
  .option('-s, --source <source>', 'Data source to fetch from (ibm, koi)', 'ibm')
  .option('-u, --url <url>', 'Custom API URL to fetch banned packages from')
  .option('--data-format <format>', 'Data format for custom URL (json, csv)', 'json')
  .option('-p, --path <path>', 'Path to the project to scan (defaults to current directory)')
  .option('--format <format>', 'Output format (text, sarif)', 'text')
  .option('--no-cache', 'Disable caching of API responses')
  .option('--install-hook', 'Install a pre-commit hook to run worm-sign')
  .action(async (options) => {
    // Dynamic imports for ESM libraries
    const { default: chalk } = await import('chalk');
    const { default: ora } = await import('ora');
    const { default: boxen } = await import('boxen');
    const { default: gradient } = await import('gradient-string');

    // Dune-themed gradient
    const duneGradient = gradient(['#F4A460', '#D2691E', '#8B4513']); // Sandy colors

    if (options.installHook) {
        try {
            const fs = require('fs');
            const hooksDir = path.join(process.cwd(), '.git', 'hooks');
            if (!fs.existsSync(hooksDir)) {
                console.error(chalk.red('Error: .git/hooks directory not found. Is this a git repository?'));
                process.exit(1);
            }
            const hookPath = path.join(hooksDir, 'pre-commit');
            const hookScript = `#!/bin/sh
# worm-sign pre-commit hook
echo "🪱 Running worm-sign..."
npx worm-sign --fetch --source koi
`;
            fs.writeFileSync(hookPath, hookScript, { mode: 0o755 });
            console.log(chalk.green('✅ Pre-commit hook installed successfully!'));
            console.log(chalk.dim('worm-sign will now run before every commit.'));
            process.exit(0);
        } catch (error) {
            console.error(chalk.red(`Error installing hook: ${error.message}`));
            process.exit(1);
        }
    }

    if (options.format === 'text') {
        console.log(boxen(duneGradient('WORM SIGN\nShai Hulud Scanner'), { padding: 1, borderStyle: 'round', borderColor: 'yellow', title: 'v' + version, titleAlignment: 'right' }));
    }

    try {
      const projectRoot = resolveProjectRoot(options.path);
      let bannedListSource;

      if (options.fetch) {
        const { loadCache, saveCache } = require('../src/cache');
        const { SOURCES } = require('../src/index');
        
        // Determine source configuration
        let sourceConfig;
        if (options.url) {
            sourceConfig = { url: options.url, type: options.dataFormat };
        } else {
            sourceConfig = SOURCES[options.source];
            if (!sourceConfig) {
                console.error(chalk.red(`Error: Unknown source '${options.source}'. Available sources: ${Object.keys(SOURCES).join(', ')}`));
                process.exit(1);
            }
        }

        if (options.cache) {
             // We need to know if the cached data is from the same source.
             // The current cache implementation doesn't store metadata.
             // For safety, let's only use cache if we are sure.
             // Let's just try to load it.
            bannedListSource = loadCache();
            if (bannedListSource && options.format === 'text') {
                console.log(chalk.dim('Using cached API data.'));
            }
        }

        if (!bannedListSource) {
            const spinner = options.format === 'text' ? ora('Fetching vulnerable packages...').start() : null;
            try {
              bannedListSource = await fetchFromApi(sourceConfig);
              if (spinner) {
                  spinner.succeed(chalk.green(`Fetched ${bannedListSource.length} packages.`));
              }
              if (options.cache) {
                  saveCache(bannedListSource);
              }
            } catch (error) {
              if (spinner) {
                  const sourceName = options.url ? 'custom URL' : `'${options.source}'`;
                  spinner.warn(chalk.yellow(`Failed to fetch from ${sourceName}: ${error.message}. Falling back to local list.`));
              }
            }
        }
      }

      if (!bannedListSource) {
          const dataDir = resolveDataDir();
          let bannedListPath = path.join(dataDir, 'vuls.csv');
          
          if (!require('fs').existsSync(bannedListPath)) {
              bannedListPath = path.join(dataDir, 'scripts', 'DO-NOT-USE-LIST-09-21-2025.csv');
          }

          if (!require('fs').existsSync(bannedListPath)) {
               bannedListPath = path.join(dataDir, 'DO-NOT-USE-LIST-09-21-2025.csv');
          }
          bannedListSource = bannedListPath;
          if (options.format === 'text') {
            console.log(chalk.blue(`Using local banned list: ${bannedListPath}`));
          }
      }

      if (options.format === 'text') {
        console.log(chalk.blue(`Scanning project at: ${projectRoot}`));
      }

      const { matches, warnings } = await scanProject(projectRoot, bannedListSource);

      let reporter;
      try {
        reporter = require(`../src/reporters/${options.format}`);
      } catch (e) {
        console.error(chalk.red(`Error: Unknown format '${options.format}'`));
        process.exit(1);
      }

      const output = reporter.report(matches, warnings, projectRoot, { chalk, boxen });
      console.log(output);

      if (matches.length > 0) {
        process.exit(1);
      } else {
        process.exit(0);
      }

    } catch (error) {
      console.error(chalk.red(`Error: ${error.message}`));
      
      // Actionable advice
      if (error.message.includes('package.json not found')) {
          console.log(chalk.dim('Hint: Are you in the root directory of your Node.js project?'));
      } else if (error.message.includes('no lockfile was found')) {
          console.log(chalk.dim('Hint: Run your package manager\'s install command (e.g., `npm install`) to generate a lockfile.'));
      } else if (error.message.includes('Unable to determine which package manager')) {
          console.log(chalk.dim('Hint: Ensure you have a lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml) or set the "packageManager" field in package.json.'));
      } else if (error.message.includes('API request failed')) {
          console.log(chalk.dim('Hint: Check your internet connection or try using --source koi for an alternative data source.'));
      }

      process.exit(2);
    }
  });

program.parse();
