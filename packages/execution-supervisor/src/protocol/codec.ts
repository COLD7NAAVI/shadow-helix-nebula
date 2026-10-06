/**
 * Shadow : Helix Nebula (SHN) — Sandboxed Worker Protocol Codec
 *
 * Encodes, decodes, and validates worker protocol messages fail-closed.
 */

import { ok, err, type Result } from '@shn/shared-kernel';
import {
  PROTOCOL_VERSION,
  MAX_MESSAGE_BYTES,
  type WorkerToSupervisorMessage,
  type SupervisorToWorkerMessage,
  type WorkerStartupMessage,
  type WorkerHeartbeatMessage,
  type WorkerOutputMessage,
  type WorkerCompletedMessage,
  type WorkerFailedMessage,
  type SupervisorInitMessage,
  type SupervisorCancelMessage,
  type SupervisorTerminateMessage,
} from './messages.js';

export function encodeProtocolMessage(
  msg: WorkerToSupervisorMessage | SupervisorToWorkerMessage
): string {
  return JSON.stringify(msg) + '\n';
}

export function decodeWorkerMessage(
  raw: string
): Result<WorkerToSupervisorMessage, string> {
  const trimmed = raw.trim();
  if (!trimmed) {
    return err('Empty worker protocol line');
  }

  if (Buffer.byteLength(trimmed, 'utf8') > MAX_MESSAGE_BYTES) {
    return err(`Worker message exceeds maximum allowed size of ${MAX_MESSAGE_BYTES} bytes`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (e) {
    return err(`Malformed worker JSON message: ${e instanceof Error ? e.message : String(e)}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return err('Worker message must be a JSON object');
  }

  const obj = parsed as Record<string, unknown>;
  const type = obj['type'];
  if (typeof type !== 'string') {
    return err('Worker message missing required string field: type');
  }

  switch (type) {
    case 'STARTUP': {
      const version = obj['version'];
      const workerId = obj['workerId'];
      if (typeof version !== 'string' || !version) {
        return err('STARTUP message missing required string field: version');
      }
      if (version !== PROTOCOL_VERSION) {
        return err(`Unsupported worker protocol version '${version}', expected '${PROTOCOL_VERSION}'`);
      }
      if (typeof workerId !== 'string' || !workerId) {
        return err('STARTUP message missing required string field: workerId');
      }
      const msg: WorkerStartupMessage = {
        type: 'STARTUP',
        version,
        workerId,
      };
      return ok(msg);
    }

    case 'HEARTBEAT': {
      const workerId = obj['workerId'];
      const timestamp = obj['timestamp'];
      if (typeof workerId !== 'string' || !workerId) {
        return err('HEARTBEAT message missing required string field: workerId');
      }
      if (typeof timestamp !== 'string' || !timestamp) {
        return err('HEARTBEAT message missing required string field: timestamp');
      }
      const metricsObj = obj['metrics'] as Record<string, unknown> | undefined;
      const metrics =
        metricsObj && typeof metricsObj === 'object'
          ? {
              memoryRssBytes:
                typeof metricsObj['memoryRssBytes'] === 'number'
                  ? metricsObj['memoryRssBytes']
                  : undefined,
              cpuPercent:
                typeof metricsObj['cpuPercent'] === 'number'
                  ? metricsObj['cpuPercent']
                  : undefined,
            }
          : undefined;
      const msg: WorkerHeartbeatMessage = {
        type: 'HEARTBEAT',
        workerId,
        timestamp,
        metrics,
      };
      return ok(msg);
    }

    case 'OUTPUT': {
      const stream = obj['stream'];
      const data = obj['data'];
      if (stream !== 'stdout' && stream !== 'stderr') {
        return err("OUTPUT message stream must be 'stdout' or 'stderr'");
      }
      if (typeof data !== 'string') {
        return err('OUTPUT message data must be a string');
      }
      const msg: WorkerOutputMessage = {
        type: 'OUTPUT',
        stream,
        data,
      };
      return ok(msg);
    }

    case 'COMPLETED': {
      const exitCode = obj['exitCode'];
      if (typeof exitCode !== 'number' || !Number.isInteger(exitCode)) {
        return err('COMPLETED message exitCode must be an integer');
      }
      const msg: WorkerCompletedMessage = {
        type: 'COMPLETED',
        exitCode,
        payload: obj['payload'],
        artifacts: Array.isArray(obj['artifacts']) ? (obj['artifacts'] as any) : undefined,
      };
      return ok(msg);
    }

    case 'FAILED': {
      const error = obj['error'];
      if (typeof error !== 'string' || !error) {
        return err('FAILED message missing required string field: error');
      }
      const msg: WorkerFailedMessage = {
        type: 'FAILED',
        error,
        details: obj['details'],
      };
      return ok(msg);
    }

    default:
      return err(`Unknown worker message type: '${String(type)}'`);
  }
}

export function decodeSupervisorMessage(
  raw: string
): Result<SupervisorToWorkerMessage, string> {
  const trimmed = raw.trim();
  if (!trimmed) {
    return err('Empty supervisor protocol line');
  }

  if (Buffer.byteLength(trimmed, 'utf8') > MAX_MESSAGE_BYTES) {
    return err(`Supervisor message exceeds maximum allowed size of ${MAX_MESSAGE_BYTES} bytes`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (e) {
    return err(`Malformed supervisor JSON message: ${e instanceof Error ? e.message : String(e)}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return err('Supervisor message must be a JSON object');
  }

  const obj = parsed as Record<string, unknown>;
  const type = obj['type'];
  if (typeof type !== 'string') {
    return err('Supervisor message missing required string field: type');
  }

  switch (type) {
    case 'INIT': {
      const version = obj['version'];
      const executionId = obj['executionId'];
      const target = obj['target'];
      const action = obj['action'];
      if (typeof version !== 'string' || version !== PROTOCOL_VERSION) {
        return err(`Unsupported supervisor protocol version: '${String(version)}'`);
      }
      if (typeof executionId !== 'string' || !executionId) {
        return err('INIT message missing executionId');
      }
      if (typeof target !== 'string' || !target) {
        return err('INIT message missing target');
      }
      if (typeof action !== 'string' || !action) {
        return err('INIT message missing action');
      }
      const msg: SupervisorInitMessage = {
        type: 'INIT',
        version,
        executionId,
        target,
        action,
        payload: obj['payload'],
      };
      return ok(msg);
    }

    case 'CANCEL': {
      const reason = obj['reason'];
      const gracePeriodMs = obj['gracePeriodMs'];
      if (typeof reason !== 'string' || !reason) {
        return err('CANCEL message missing reason');
      }
      const grace = typeof gracePeriodMs === 'number' ? gracePeriodMs : 2000;
      const msg: SupervisorCancelMessage = {
        type: 'CANCEL',
        reason,
        gracePeriodMs: grace,
      };
      return ok(msg);
    }

    case 'TERMINATE': {
      const reason = obj['reason'];
      if (typeof reason !== 'string' || !reason) {
        return err('TERMINATE message missing reason');
      }
      const msg: SupervisorTerminateMessage = {
        type: 'TERMINATE',
        reason,
      };
      return ok(msg);
    }

    default:
      return err(`Unknown supervisor message type: '${String(type)}'`);
  }
}
