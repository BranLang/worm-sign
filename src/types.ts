export interface LockPackageResult {
    packages: Map<string, Set<string>>; // version -> set of versions
    packageIntegrity?: Map<string, Map<string, string>>; // name -> version -> integrity hash
    warnings: string[];
    success: boolean;
}

export interface PackageManagerHandler {
    id: string;
    label: string;
    lockFiles: string[];
    detectFromPackageManagerField(fieldValue: string): boolean;
    findLockFile(repoRoot: string): string | null;
    loadLockPackages(lockPath: string): LockPackageResult;
}

export interface BannedPackage {
    name: string;
    version: string;
    reason?: string;
    section?: string;
    integrity?: string; // SHA-1 or SHA-512 hash
}

export interface ScanMatch {
    name: string;
    version: string;
    section: string;
}
