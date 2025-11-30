import * as fs from 'fs';
import * as path from 'path';
import { loadCsv, parseCsv } from '../src/utils/csv';
import { fetchFromApi } from '../src/index';
import { BannedPackage } from '../src/types';
import { stringify } from 'csv-stringify/sync';

const sourcesDir = path.join(__dirname, '../sources');
const outputFile = path.join(sourcesDir, 'known-threats.csv');

async function addSource(source: string) {
    console.log(`Adding source: ${source}`);

    let newPackages: BannedPackage[] = [];

    if (source.startsWith('http')) {
        try {
            // Determine type based on extension or default to csv
            const type = source.endsWith('.json') ? 'json' : 'csv';
            console.log(`Fetching from URL (${type})...`);
            newPackages = await fetchFromApi({ url: source, type });
        } catch (e: any) {
            console.error(`Failed to fetch from URL: ${e.message}`);
            process.exit(1);
        }
    } else {
        if (!fs.existsSync(source)) {
            console.error(`File not found: ${source}`);
            process.exit(1);
        }
        console.log('Loading from local file...');
        newPackages = loadCsv(source);
    }

    console.log(`Loaded ${newPackages.length} new packages.`);

    // Load existing
    let existingPackages: BannedPackage[] = [];
    if (fs.existsSync(outputFile)) {
        console.log('Loading existing known-threats.csv...');
        existingPackages = loadCsv(outputFile);
    }

    const allPackages = [...existingPackages, ...newPackages];
    console.log(`Total packages before deduplication: ${allPackages.length}`);

    // Deduplicate
    const uniqueMap = new Map<string, BannedPackage>();
    allPackages.forEach(p => {
        const key = `${p.name}@${p.version}`;
        if (!uniqueMap.has(key)) {
            uniqueMap.set(key, p);
        }
    });

    console.log(`Unique packages: ${uniqueMap.size}`);
    console.log(`Added ${uniqueMap.size - existingPackages.length} new unique packages.`);

    const sortedPackages = Array.from(uniqueMap.values()).sort((a, b) => {
        return a.name.localeCompare(b.name) || a.version.localeCompare(b.version);
    });

    const csvOutput = stringify(sortedPackages, {
        header: true,
        columns: ['name', 'version', 'reason', 'integrity']
    });

    fs.writeFileSync(outputFile, csvOutput);
    console.log(`Updated list written to ${outputFile}`);
}

const sourceArg = process.argv[2];
if (!sourceArg) {
    console.error('Usage: npx ts-node scripts/add-source.ts <url_or_file_path>');
    process.exit(1);
}

addSource(sourceArg);
