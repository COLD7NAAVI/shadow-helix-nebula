import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  encodeProtocolMessage,
  decodeWorkerMessage,
  decodeSupervisorMessage,
  PROTOCOL_VERSION,
  MAX_MESSAGE_BYTES,
  type WorkerStartupMessage,
  type WorkerHeartbeatMessage,
  type WorkerOutputMessage,
  type WorkerCompletedMessage,
  type WorkerFailedMessage,
  type SupervisorInitMessage,
  type SupervisorCancelMessage,
  type SupervisorTerminateMessage,
} from '../../dist/index.js';

describe('Worker Protocol Codec (Unit Tests)', () => {
  describe('WorkerToSupervisor Messages', () => {
    it('should encode and decode STARTUP message', () => {
      const msg: WorkerStartupMessage = {
        type: 'STARTUP',
        version: PROTOCOL_VERSION,
        workerId: 'worker-12345',
      };
      const encoded = encodeProtocolMessage(msg);
      assert.ok(encoded.endsWith('\n'));

      const decoded = decodeWorkerMessage(encoded);
      assert.equal(decoded.isOk, true);
      assert.deepEqual(decoded.unwrapOr(null as any), msg);
    });

    it('should encode and decode HEARTBEAT message with metrics', () => {
      const msg: WorkerHeartbeatMessage = {
        type: 'HEARTBEAT',
        workerId: 'worker-12345',
        timestamp: '2026-10-06T12:00:00.000Z',
        metrics: {
          memoryRssBytes: 10485760,
          cpuPercent: 12.5,
        },
      };
      const encoded = encodeProtocolMessage(msg);
      const decoded = decodeWorkerMessage(encoded);
      assert.equal(decoded.isOk, true);
      assert.deepEqual(decoded.unwrapOr(null as any), msg);
    });

    it('should encode and decode OUTPUT message for stdout and stderr', () => {
      const msgStdout: WorkerOutputMessage = {
        type: 'OUTPUT',
        stream: 'stdout',
        data: 'Scan output line 1\n',
      };
      const decStdout = decodeWorkerMessage(encodeProtocolMessage(msgStdout));
      assert.equal(decStdout.isOk, true);
      assert.deepEqual(decStdout.unwrapOr(null as any), msgStdout);

      const msgStderr: WorkerOutputMessage = {
        type: 'OUTPUT',
        stream: 'stderr',
        data: 'Warning: target slow to respond\n',
      };
      const decStderr = decodeWorkerMessage(encodeProtocolMessage(msgStderr));
      assert.equal(decStderr.isOk, true);
      assert.deepEqual(decStderr.unwrapOr(null as any), msgStderr);
    });

    it('should encode and decode COMPLETED message with payload and artifacts', () => {
      const msg: WorkerCompletedMessage = {
        type: 'COMPLETED',
        exitCode: 0,
        payload: { openPorts: [80, 443], banner: 'nginx' },
        artifacts: [
          {
            name: 'scan.xml',
            contentSha256: 'abcdef123456',
            storageUri: 'blob://evidence/scan.xml',
            byteSize: 1024,
            mimeType: 'application/xml',
          },
        ],
      };
      const encoded = encodeProtocolMessage(msg);
      const decoded = decodeWorkerMessage(encoded);
      assert.equal(decoded.isOk, true);
      assert.deepEqual(decoded.unwrapOr(null as any), msg);
    });

    it('should encode and decode FAILED message', () => {
      const msg: WorkerFailedMessage = {
        type: 'FAILED',
        error: 'Target unreachable: Connection refused',
        details: 'Error: Connection refused\n    at Socket.connect',
      };
      const encoded = encodeProtocolMessage(msg);
      const decoded = decodeWorkerMessage(encoded);
      assert.equal(decoded.isOk, true);
      assert.deepEqual(decoded.unwrapOr(null as any), msg);
    });

    it('should reject malformed or invalid worker messages fail-closed', () => {
      // Empty line
      assert.equal(decodeWorkerMessage('').isErr, true);
      assert.equal(decodeWorkerMessage('   \n').isErr, true);

      // Invalid JSON
      assert.equal(decodeWorkerMessage('{ invalid json }').isErr, true);

      // Not an object
      assert.equal(decodeWorkerMessage('"hello"').isErr, true);
      assert.equal(decodeWorkerMessage('[1, 2, 3]').isErr, true);

      // Missing or unknown type
      assert.equal(decodeWorkerMessage('{}').isErr, true);
      assert.equal(decodeWorkerMessage('{"type": "UNKNOWN"}').isErr, true);

      // STARTUP with unsupported version
      assert.equal(decodeWorkerMessage('{"type": "STARTUP", "version": "99.0", "workerId": "w1"}').isErr, true);

      // STARTUP missing workerId
      assert.equal(decodeWorkerMessage('{"type": "STARTUP", "version": "1.0"}').isErr, true);

      // OUTPUT with invalid stream
      assert.equal(decodeWorkerMessage('{"type": "OUTPUT", "stream": "invalid", "data": "abc"}').isErr, true);

      // Exceeding MAX_MESSAGE_BYTES
      const hugeLine = JSON.stringify({ type: 'OUTPUT', stream: 'stdout', data: 'x'.repeat(MAX_MESSAGE_BYTES + 10) });
      assert.equal(decodeWorkerMessage(hugeLine).isErr, true);
    });
  });

  describe('SupervisorToWorker Messages', () => {
    it('should encode and decode INIT message', () => {
      const msg: SupervisorInitMessage = {
        type: 'INIT',
        version: PROTOCOL_VERSION,
        executionId: '01955ef2-2253-7c5e-85a7-d868924ff9cb',
        target: '192.168.1.1',
        action: 'scan',
        payload: { rate: 1000 },
      };
      const encoded = encodeProtocolMessage(msg);
      const decoded = decodeSupervisorMessage(encoded);
      assert.equal(decoded.isOk, true);
      assert.deepEqual(decoded.unwrapOr(null as any), msg);
    });

    it('should encode and decode CANCEL message', () => {
      const msg: SupervisorCancelMessage = {
        type: 'CANCEL',
        reason: 'Operator cancelled task',
        gracePeriodMs: 2000,
      };
      const encoded = encodeProtocolMessage(msg);
      const decoded = decodeSupervisorMessage(encoded);
      assert.equal(decoded.isOk, true);
      assert.deepEqual(decoded.unwrapOr(null as any), msg);
    });

    it('should encode and decode TERMINATE message', () => {
      const msg: SupervisorTerminateMessage = {
        type: 'TERMINATE',
        reason: 'Resource ceiling breached',
      };
      const encoded = encodeProtocolMessage(msg);
      const decoded = decodeSupervisorMessage(encoded);
      assert.equal(decoded.isOk, true);
      assert.deepEqual(decoded.unwrapOr(null as any), msg);
    });

    it('should reject malformed or invalid supervisor messages fail-closed', () => {
      assert.equal(decodeSupervisorMessage('').isErr, true);
      assert.equal(decodeSupervisorMessage('not json').isErr, true);
      assert.equal(decodeSupervisorMessage('{"type": "INIT", "version": "99.0"}').isErr, true);
      assert.equal(decodeSupervisorMessage('{"type": "UNKNOWN"}').isErr, true);
    });
  });
});
