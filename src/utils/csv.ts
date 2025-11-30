import * as fs from 'fs';
import { parse } from 'csv-parse/sync';
import { CompromisedPackage } from '../types';

export function loadCsv(filePath: string): CompromisedPackage[] {
    const raw = fs.readFileSync(filePath, 'utf8');
    return parseCsv(raw);
}

export function parseCsv(raw: string): CompromisedPackage[] {
    try {
        const parsed = parse(raw, {
            columns: true,
            skip_empty_lines: true,
            trim: true,
            relax_column_count: true
        });

        return parsed.map((record: Record<string, string>) => {
            // Try to find name and version fields
            const name = record['package name'] || record['name'] || record['Package Name'] || record['package_name'] || Object.values(record)[0];
            const version = record['package version'] || record['version'] || record['Package Version'] || record['package_version'] || Object.values(record)[1] || '';
            const reason = record['MSC ID'] || record['reason'] || '';
            const integrity = record['integrity'] || record['hash'] || record['shasum'] || undefined;

            return { name, version, reason, integrity };
        }).filter((p: CompromisedPackage) => !!p.name) as CompromisedPackage[];

    } catch (e) {
        console.warn('CSV parse warning:', e instanceof Error ? e.message : String(e));
        return [];
    }
}
