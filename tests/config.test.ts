import { loadConfig, defaultConfig } from '../src/config';
import * as path from 'path';

describe('Configuration Loading', () => {
    const fixturesDir = path.join(__dirname, 'fixtures', 'config');

    it('should return default config if no config file found', () => {
        const config = loadConfig('/non/existent/path');
        expect(config).toEqual(defaultConfig);
    });

    // Note: We would need to mock cosmiconfig or create actual config files to test loading.
    // For now, we rely on the fact that cosmiconfig is a proven library.
    // We can add a simple integration test later if needed.
});
