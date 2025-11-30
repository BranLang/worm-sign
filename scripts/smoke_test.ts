import { spawnSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

// Dynamic imports for ESM-only packages
async function run() {
    console.clear();
    const { default: chalk } = await import('chalk');
    const { default: boxen } = await import('boxen');
    const { default: ora } = await import('ora');
    const { default: gradient } = await import('gradient-string');

    const binPath = path.join(__dirname, '..', 'dist', 'bin', 'scan.js');
    const fixturesDir = path.join(__dirname, '..', 'tests', 'fixtures');

    console.log(gradient.morning('\n  WORM SIGN SMOKE TESTS  \n'));

    let bannedOutput = '';

    function runScan(fixtureName: string, expectFailure: boolean) {
        const spinner = ora(`Running smoke test for ${chalk.cyan(fixtureName)}...`).start();
        const fixturePath = path.join(fixturesDir, fixtureName);

        const start = Date.now();
        const result = spawnSync('node', [binPath, '-p', fixturePath], { encoding: 'utf8' });
        const duration = Date.now() - start;

        if (expectFailure) {
            if (result.status === 1) {
                spinner.succeed(`${chalk.bold(fixtureName)}: ${chalk.green('Passed')} (Failed as expected) ${chalk.gray(`(${duration}ms)`)}`);
                if (fixtureName === 'npm-banned' || fixtureName === 'npm-critical-breach') {
                    bannedOutput += `\n--- ${fixtureName} ---\n` + result.stdout;
                }
            } else {
                spinner.fail(`${chalk.bold(fixtureName)}: ${chalk.red('Failed')} (Expected failure, got success)`);
                console.error(boxen(result.stdout + '\n' + result.stderr, { title: 'Output', borderColor: 'red' }));
                process.exit(1);
            }
        } else {
            if (result.status === 0) {
                spinner.succeed(`${chalk.bold(fixtureName)}: ${chalk.green('Passed')} (Success as expected) ${chalk.gray(`(${duration}ms)`)}`);
            } else {
                spinner.fail(`${chalk.bold(fixtureName)}: ${chalk.red('Failed')} (Expected success, got failure)`);
                console.error(boxen(result.stdout + '\n' + result.stderr, { title: 'Output', borderColor: 'red' }));
                process.exit(1);
            }
        }
    }

    // Ensure build exists
    if (!fs.existsSync(binPath)) {
        console.error(chalk.red('❌ Build not found. Run `npm run build` first.'));
        process.exit(1);
    }

    runScan('npm-ok', false);
    runScan('npm-banned', true);
    runScan('npm-critical-breach', true);
    // runScan('yarn-ok', false);
    // runScan('yarn-banned', true);
    // runScan('pnpm-ok', false);
    // runScan('pnpm-banned', true);

    console.log(boxen(chalk.green('All smoke tests passed!'), { padding: 1, borderColor: 'green', borderStyle: 'round' }));

    if (bannedOutput) {
        console.log('\n' + gradient.atlas('  DETECTION DEMO OUTPUT  '));
        console.log(boxen(bannedOutput, { padding: 1, borderColor: 'red', borderStyle: 'double', title: 'npm-banned output' }));
    }
}

run().catch(err => {
    console.error(err);
    process.exit(1);
});
