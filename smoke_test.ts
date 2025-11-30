import { spawnSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

const binPath = path.join(__dirname, 'dist', 'bin', 'scan.js');
const fixturesDir = path.join(__dirname, 'tests', 'fixtures');

function runScan(fixtureName: string, expectFailure: boolean) {
    console.log(`Running smoke test for ${fixtureName}...`);
    const fixturePath = path.join(fixturesDir, fixtureName);
    const result = spawnSync('node', [binPath, '-p', fixturePath], { encoding: 'utf8' });

    if (expectFailure) {
        if (result.status === 1) {
            console.log(`✅ ${fixtureName}: Failed as expected.`);
        } else {
            console.error(`❌ ${fixtureName}: Expected failure (1), got ${result.status}`);
            console.error(result.stdout);
            console.error(result.stderr);
            process.exit(1);
        }
    } else {
        if (result.status === 0) {
            console.log(`✅ ${fixtureName}: Passed as expected.`);
        } else {
            console.error(`❌ ${fixtureName}: Expected success (0), got ${result.status}`);
            console.error(result.stdout);
            console.error(result.stderr);
            process.exit(1);
        }
    }
}

// Ensure build exists
if (!fs.existsSync(binPath)) {
    console.error('❌ Build not found. Run `npm run build` first.');
    process.exit(1);
}

runScan('npm-ok', false);
runScan('npm-banned', true);
// runScan('yarn-ok', false);
// runScan('yarn-banned', true);
// runScan('pnpm-ok', false);
// runScan('pnpm-banned', true);

console.log('\nAll smoke tests passed!');
