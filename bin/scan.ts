#!/usr/bin/env node

import * as path from 'path';
import * as fs from 'fs';
import { program } from 'commander';
import { scanProject, fetchBannedPackages, loadCsv, loadJson } from '../src/index';
// @ts-ignore
import pkg from '../package.json';

const version = pkg.version;

const scriptDir = __dirname;
// Default to the bundled list in the package
// Handle both ts-node (bin/scan.ts -> root is ..) and dist (dist/bin/scan.js -> root is ../..)
let defaultDataDir = path.resolve(scriptDir, '..', '..');
if (fs.existsSync(path.join(scriptDir, '..', 'package.json'))) {
  // If package.json is in the parent of bin, then that parent is the root.
  // This happens if we are running from root/bin/scan.ts (ts-node)
  // BUT if we are in dist/bin, dist/package.json might not exist, so we go up two levels.
  // However, if dist/package.json DOES exist (e.g. copied for distribution), we might want that.
  // But here we want the source root where 'sources' dir lives.
  // Let's check if 'sources' exists in the candidate dir.
  const candidate = path.resolve(scriptDir, '..');
  if (fs.existsSync(path.join(candidate, 'sources'))) {
    defaultDataDir = candidate;
  }
}

function resolveProjectRoot(override?: string): string {
  return override
    ? path.resolve(override)
    : process.env.PKG_SCAN_ROOT
      ? path.resolve(process.env.PKG_SCAN_ROOT)
      : process.cwd();
}

function resolveDataDir(): string {
  const override = process.env.PKG_SCAN_DATA_ROOT;
  const dir = override ? path.resolve(override) : defaultDataDir;
  return dir;
}

program
  .name('worm-sign')
  .description(
    'Scan your project for packages compromised by the Shai Hulud malware (supports name/version and hash detection).',
  )
  .version(version)
  .option('-f, --fetch', 'Fetch the latest banned packages from the API')

  .option('--offline', 'Disable fetching of remote sources')
  .option('-u, --url <url>', 'Custom API URL to fetch banned packages from')
  .option('--data-format <format>', 'Data format for custom URL (json, csv)', 'json')
  .option('-p, --path <path>', 'Path to the project to scan (defaults to current directory)')
  .option('--format <format>', 'Output format (text, sarif)', 'text')
  .option('--no-cache', 'Disable caching of API responses')
  .option('--install-hook', 'Install a pre-commit hook to run worm-sign')
  .option('--dry-run', 'Run scan but always exit with 0 (useful for CI)')
  .option('--insecure', 'Disable SSL certificate verification (use with caution)')
  .option('--debug', 'Enable debug logging')
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
        const hooksDir = path.join(process.cwd(), '.git', 'hooks');
        if (!fs.existsSync(hooksDir)) {
          console.error(
            chalk.red('Error: .git/hooks directory not found. Is this a git repository?'),
          );
          process.exit(1);
        }
        const hookPath = path.join(hooksDir, 'pre-commit');
        const hookScript = `#!/bin/sh
# worm-sign pre-commit hook
echo "🪱 Running worm-sign..."
npx worm-sign --fetch
`;
        fs.writeFileSync(hookPath, hookScript, { mode: 0o755 });
        console.log(chalk.green('✅ Pre-commit hook installed successfully!'));
        console.log(chalk.dim('worm-sign will now run before every commit.'));
        process.exit(0);
      } catch (error: any) {
        console.error(chalk.red(`Error installing hook: ${error.message}`));
        process.exit(1);
      }
    }

    if (options.format === 'text') {
      console.log(
        boxen(duneGradient('WORM SIGN\nShai Hulud Scanner'), {
          padding: 1,
          borderStyle: 'round',
          borderColor: 'yellow',
          title: 'v' + version,
          titleAlignment: 'right',
        }),
      );
    }

    try {
      const projectRoot = resolveProjectRoot(options.path);
      const dataDir = resolveDataDir();
      const sourcesDir = path.join(dataDir, 'sources');

      const allBanned: any[] = [];
      const sourcesToFetch: any[] = [];
      let foundSources = false;

      // 1. Load from sources directory
      if (fs.existsSync(sourcesDir) && fs.statSync(sourcesDir).isDirectory()) {
        const files = fs.readdirSync(sourcesDir);
        for (const file of files) {
          const filePath = path.join(sourcesDir, file);
          try {
            if (file.endsWith('.csv')) {
              const packages = loadCsv(filePath);
              if (packages.length > 0) {
                allBanned.push(...packages);
                foundSources = true;
                if (options.format === 'text') {
                  console.log(chalk.blue(`Loaded ${packages.length} packages from: ${file}`));
                }
              }
            } else if (file.endsWith('.json')) {
              const raw = fs.readFileSync(filePath, 'utf8');
              try {
                const json = JSON.parse(raw);
                if (Array.isArray(json) || (json.packages && Array.isArray(json.packages))) {
                  const packages = loadJson(filePath);
                  if (packages.length > 0) {
                    allBanned.push(...packages);
                    foundSources = true;
                    if (options.format === 'text') {
                      console.log(chalk.blue(`Loaded ${packages.length} packages from: ${file}`));
                    }
                  }
                } else if (json.url && json.type) {
                  // Remote source config
                  if (!options.offline) {
                    sourcesToFetch.push({ ...json, name: file });
                  }
                }
              } catch (e) {
                console.warn(chalk.yellow(`Warning: Failed to parse JSON ${file}: ${e}`));
              }
            }
          } catch (e: any) {
            console.warn(chalk.yellow(`Warning: Failed to load ${file}: ${e.message}`));
          }
        }
      }

      // 2. Add custom URL if provided
      if (options.url) {
        sourcesToFetch.push({
          url: options.url,
          type: options.dataFormat,
          name: 'custom-cli',
          insecure: options.insecure,
        });
      }

      // 3. Fetch remote sources
      // We fetch if there are remote sources defined.
      // Note: Default remote sources are skipped above if --offline is set,
      // but custom --url is always added to sourcesToFetch.
      if (sourcesToFetch.length > 0) {
        const spinner =
          options.format === 'text'
            ? ora(`Fetching from ${sourcesToFetch.length} remote source(s)...`).start()
            : null;
        try {
          // Use caching if enabled
          if (options.cache) {
            // TODO: Implement granular caching per source?
            // For now, the existing cache logic was monolithic.
            // We might skip complex caching refactor for now and just fetch.
            // Or we can try to load cache.
          }

          const { packages: fetchedPackages, errors } = await fetchBannedPackages(sourcesToFetch);
          allBanned.push(...fetchedPackages);
          foundSources = true;

          if (spinner) {
            if (errors.length > 0) {
              spinner.warn(
                chalk.yellow(
                  `Fetched ${fetchedPackages.length} packages, but some sources failed:\n${errors.map((e) => '  - ' + e).join('\n')}`,
                ),
              );
            } else {
              spinner.succeed(
                chalk.green(`Fetched ${fetchedPackages.length} packages from remote sources.`),
              );
            }
          } else if (errors.length > 0) {
            errors.forEach((e) => console.warn(chalk.yellow(`Warning: ${e}`)));
          }
        } catch (error: any) {
          // This catch block might not be reached anymore unless fetchBannedPackages throws unexpected error
          if (spinner) {
            spinner.fail(chalk.red(`Error: Unexpected failure during fetch: ${error.message}`));
          }
        }
      }

      // Fallback to legacy vuls.csv in root if ABSOLUTELY nothing found
      if (!foundSources && sourcesToFetch.length === 0) {
        const legacyPath = path.join(dataDir, 'vuls.csv');
        if (fs.existsSync(legacyPath)) {
          const packages = loadCsv(legacyPath);
          allBanned.push(...packages);
          foundSources = true;
          if (options.format === 'text') {
            console.log(chalk.blue(`Using local banned list: ${legacyPath}`));
          }
        }
      }

      if (!foundSources && allBanned.length === 0) {
        console.warn(chalk.yellow('Warning: No banned packages loaded. Scan will likely pass.'));
      }

      const bannedListSource = allBanned;

      if (options.format === 'text') {
        console.log(chalk.blue(`Scanning project at: ${projectRoot}`));
      }

      const { matches, warnings } = await scanProject(projectRoot, bannedListSource, {
        debug: options.debug,
      });

      let reporter;
      try {
        reporter = await import(`../src/reporters/${options.format}.js`);
      } catch {
        console.error(chalk.red(`Error: Unknown format '${options.format}'`));
        process.exit(1);
      }

      const output = reporter.report(matches, warnings, projectRoot, { chalk, boxen });
      console.log(output);

      if (matches.length > 0) {
        if (options.dryRun) {
          console.log(chalk.yellow('\n[DRY RUN] Vulnerabilities found, but exiting with 0.'));
          process.exit(0);
        }
        process.exit(1);
      } else {
        process.exit(0);
      }
    } catch (error: any) {
      console.error(chalk.red(`Error: ${error.message}`));

      // Actionable advice
      if (error.message.includes('package.json not found')) {
        console.log(chalk.dim('Hint: Are you in the root directory of your Node.js project?'));
      } else if (error.message.includes('no lockfile was found')) {
        console.log(
          chalk.dim(
            "Hint: Run your package manager's install command (e.g., `npm install`) to generate a lockfile.",
          ),
        );
      } else if (error.message.includes('Unable to determine which package manager')) {
        console.log(
          chalk.dim(
            'Hint: Ensure you have a lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml) or set the "packageManager" field in package.json.',
          ),
        );
      } else if (error.message.includes('API request failed')) {
        console.log(
          chalk.dim(
            'Hint: Check your internet connection or try using --source koi for an alternative data source.',
          ),
        );
      }

      process.exit(2);
    }
  });

program.parse();
