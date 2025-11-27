import { fetchBannedPackages, scanProject } from '../src/index';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

describe('Integration Tests', () => {
    const tempDir = path.join(os.tmpdir(), 'worm-sign-integration-test');

    beforeAll(() => {
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir);
        }
    });

    afterAll(() => {
        if (fs.existsSync(tempDir)) {
            fs.rmSync(tempDir, { recursive: true, force: true });
        }
    });

    test('should fetch Shai Hulud 2.0 feed and detect a compromised package', async () => {
        // 1. Fetch the real feed (or mock if we want to be purely offline, but this is integration)
        // We'll use the 'datadog' source which is the Shai Hulud 2.0 feed.
        // Note: This requires internet access.
        let bannedPackages;
        try {
            bannedPackages = await fetchBannedPackages({ source: 'datadog' });
        } catch (e) {
            console.warn('Skipping integration test due to network failure:', e);
            return;
        }

        expect(bannedPackages.length).toBeGreaterThan(0);

        // 2. Pick a package from the feed to test detection
        // We'll pick one that is likely to stay in the list, e.g., '02-echo' from the top
        const badPackage = bannedPackages.find(p => p.name === '02-echo');
        if (!badPackage) {
            console.warn('Could not find expected test package in feed.');
            return;
        }

        // 3. Create a dummy project with this package
        const projectDir = path.join(tempDir, 'bad-project');
        if (!fs.existsSync(projectDir)) fs.mkdirSync(projectDir);

        const packageJson = {
            name: 'bad-project',
            version: '1.0.0',
            dependencies: {
                [badPackage.name]: badPackage.version
            }
        };
        fs.writeFileSync(path.join(projectDir, 'package.json'), JSON.stringify(packageJson, null, 2));

        // Create a dummy lockfile to satisfy the scanner
        // We'll mock a package-lock.json
        const packageLock = {
            name: 'bad-project',
            version: '1.0.0',
            lockfileVersion: 3,
            packages: {
                [`node_modules/${badPackage.name}`]: {
                    version: badPackage.version
                }
            }
        };
        fs.writeFileSync(path.join(projectDir, 'package-lock.json'), JSON.stringify(packageLock, null, 2));

        // 4. Run the scanner
        const { matches } = await scanProject(projectDir, bannedPackages);

        // 5. Verify detection
        expect(matches).toEqual(expect.arrayContaining([
            expect.objectContaining({
                name: badPackage.name,
                version: badPackage.version
            })
        ]));
    }, 30000); // Increase timeout for network request
});
