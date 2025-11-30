import * as fs from 'fs';
import * as path from 'path';
import { loadCsv } from '../src/utils/csv';
import { CompromisedPackage } from '../src/types';
import { stringify } from 'csv-stringify/sync';

const sourcesDir = path.join(__dirname, '../sources');
const outputFile = path.join(sourcesDir, 'known-threats.csv');

function consolidate() {
    console.log('Consolidating CSV sources...');
    const files = fs.readdirSync(sourcesDir).filter(f => f.endsWith('.csv') && f !== 'known-threats.csv');

    const allPackages: CompromisedPackage[] = [];

    for (const file of files) {
        console.log(`Loading ${file}...`);
        const filePath = path.join(sourcesDir, file);
        const packages = loadCsv(filePath);
        allPackages.push(...packages);
    }

    console.log(`Total packages loaded: ${allPackages.length}`);

    // Deduplicate
    const uniqueMap = new Map<string, CompromisedPackage>();
    allPackages.forEach(p => {
        const key = `${p.name}@${p.version}`;
        if (!uniqueMap.has(key)) {
            uniqueMap.set(key, p);
        }
    });

    console.log(`Unique packages: ${uniqueMap.size}`);

    const sortedPackages = Array.from(uniqueMap.values()).sort((a, b) => {
        return a.name.localeCompare(b.name) || a.version.localeCompare(b.version);
    });

    const csvOutput = stringify(sortedPackages, {
        header: true,
        columns: ['name', 'version', 'reason', 'integrity']
    });

    fs.writeFileSync(outputFile, csvOutput);
    console.log(`Consolidated list written to ${outputFile}`);
}

consolidate();
