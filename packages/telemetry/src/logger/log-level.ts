/**
 * Shadow : Helix Nebula (SHN) — Structured Logging Severity Levels
 */

export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error';

export const LOG_LEVEL_SEVERITY: Record<LogLevel, number> = {
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
};

export function isLogLevelEnabled(configuredLevel: LogLevel, testLevel: LogLevel): boolean {
  return LOG_LEVEL_SEVERITY[testLevel] >= LOG_LEVEL_SEVERITY[configuredLevel];
}

export function parseLogLevel(input: unknown, defaultLevel: LogLevel = 'info'): LogLevel {
  if (typeof input !== 'string') return defaultLevel;
  const lower = input.toLowerCase().trim();
  if (lower in LOG_LEVEL_SEVERITY) {
    return lower as LogLevel;
  }
  return defaultLevel;
}
