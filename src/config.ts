import { cosmiconfigSync } from 'cosmiconfig';
import { Severity } from './types';

export interface WormSignConfig {
  offline?: boolean;
  allowedSources?: string[];
  severityThreshold?: Severity;
  suppressedRules?: string[];
}

export const defaultConfig: WormSignConfig = {
  offline: false,
  allowedSources: [],
  severityThreshold: 'low',
  suppressedRules: [],
};

export function loadConfig(searchFrom: string = process.cwd()): WormSignConfig {
  const explorer = cosmiconfigSync('wormsign');
  try {
    const result = explorer.search(searchFrom);
    if (result && result.config) {
      return { ...defaultConfig, ...result.config };
    }
  } catch (error) {
    // Ignore errors, return default
    console.warn('Warning: Failed to load configuration file:', error);
  }
  return defaultConfig;
}
