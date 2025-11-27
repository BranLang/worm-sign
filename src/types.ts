export interface LockPackageResult {
    packages: Map<string, Set<string>>;
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
}

export interface ScanMatch {
    name: string;
    version: string;
    section: string;
}
