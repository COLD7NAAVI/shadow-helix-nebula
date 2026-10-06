/**
 * Shadow : Helix Nebula (SHN) — Sandboxed Worker Protocol Messages
 *
 * Deterministic Line-Delimited JSON (NDJSON) protocol exchanged between
 * trusted ExecutionSupervisor and untrusted SandboxedWorker over standard streams.
 */

import type { ExecutionArtifactReference } from '../contracts.js';

export const PROTOCOL_VERSION = '1.0';
export const MAX_MESSAGE_BYTES = 64 * 1024; // 64 KB max per protocol line

// ----------------------------------------------------------------------------
// Worker -> Supervisor Messages
// ----------------------------------------------------------------------------

export interface WorkerStartupMessage {
  readonly type: 'STARTUP';
  readonly version: string;
  readonly workerId: string;
}

export interface WorkerHeartbeatMetrics {
  readonly memoryRssBytes?: number | undefined;
  readonly cpuPercent?: number | undefined;
}

export interface WorkerHeartbeatMessage {
  readonly type: 'HEARTBEAT';
  readonly workerId: string;
  readonly timestamp: string;
  readonly metrics?: WorkerHeartbeatMetrics | undefined;
}

export interface WorkerOutputMessage {
  readonly type: 'OUTPUT';
  readonly stream: 'stdout' | 'stderr';
  readonly data: string;
}

export interface WorkerCompletedMessage {
  readonly type: 'COMPLETED';
  readonly exitCode: number;
  readonly payload?: unknown | undefined;
  readonly artifacts?: readonly ExecutionArtifactReference[] | undefined;
}

export interface WorkerFailedMessage {
  readonly type: 'FAILED';
  readonly error: string;
  readonly details?: unknown | undefined;
}

export type WorkerToSupervisorMessage =
  | WorkerStartupMessage
  | WorkerHeartbeatMessage
  | WorkerOutputMessage
  | WorkerCompletedMessage
  | WorkerFailedMessage;

// ----------------------------------------------------------------------------
// Supervisor -> Worker Messages
// ----------------------------------------------------------------------------

export interface SupervisorInitMessage {
  readonly type: 'INIT';
  readonly version: string;
  readonly executionId: string;
  readonly target: string;
  readonly action: string;
  readonly payload?: unknown | undefined;
}

export interface SupervisorCancelMessage {
  readonly type: 'CANCEL';
  readonly reason: string;
  readonly gracePeriodMs: number;
}

export interface SupervisorTerminateMessage {
  readonly type: 'TERMINATE';
  readonly reason: string;
}

export type SupervisorToWorkerMessage =
  | SupervisorInitMessage
  | SupervisorCancelMessage
  | SupervisorTerminateMessage;
