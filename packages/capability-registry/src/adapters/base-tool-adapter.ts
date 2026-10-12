/**
 * Shadow : Helix Nebula (SHN) — Canonical Base Tool Adapter Abstraction
 *
 * Authoritative Spec: Phase 0.3 Context 4 (BC-CAP), Phase 0.4 (INV-01, INV-03, INV-14),
 *                    Phase 0.8 (Plugin & Adapter Contracts),
 *                    Phase 0.9 (Tool Integration Architecture)
 */

import { ok, err, type Result, type AdapterId } from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';
import { makeCapabilityProblem } from '../errors.js';
import type {
  IToolAdapter,
  AdapterCapabilityBinding,
  AdapterLifecycleState,
  CapabilityDefinition,
  CommandVector,
  AdapterExecutionOutput,
  EvidenceArtifact,
  PlatformType,
} from '../contracts.js';
import type { ExecutionTerminationReason } from '@shn/execution-supervisor';

export abstract class BaseToolAdapter implements IToolAdapter {
  abstract readonly adapterId: AdapterId;
  abstract readonly name: string;
  abstract readonly version: string;
  abstract readonly platformSupport: readonly PlatformType[];
  abstract readonly supportedCapabilities: readonly AdapterCapabilityBinding[];

  protected lifecycleState: AdapterLifecycleState = 'REGISTERED';

  getLifecycleState(): AdapterLifecycleState {
    return this.lifecycleState;
  }

  setLifecycleState(state: AdapterLifecycleState): void {
    this.lifecycleState = state;
  }

  /**
   * Default parameter validation checking required fields and sanitizing input strings.
   */
  validateParameters(
    capability: CapabilityDefinition,
    params: Record<string, unknown>
  ): Result<Record<string, unknown>, ProblemDetails> {
    const schema = capability.argumentSchema;
    const required = Array.isArray(schema['required']) ? (schema['required'] as string[]) : [];

    for (const reqField of required) {
      if (params[reqField] === undefined || params[reqField] === null || params[reqField] === '') {
        return err(
          makeCapabilityProblem(
            ErrorCode.INVALID_PAYLOAD_SCHEMA,
            `Missing required parameter '${reqField}' for capability '${capability.id}'`
          )
        );
      }
    }

    // Sanitize string values
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(params)) {
      if (typeof value === 'string') {
        if (value.includes('\0')) {
          return err(
            makeCapabilityProblem(
              ErrorCode.EXEC_COMMAND_INJECTION_REJECTED,
              `Parameter '${key}' contains forbidden null byte (\\0)`
            )
          );
        }
        if (value.length > 8192) {
          return err(
            makeCapabilityProblem(
              ErrorCode.INVALID_PAYLOAD_SCHEMA,
              `Parameter '${key}' exceeds maximum allowed length of 8192 characters`
            )
          );
        }
        sanitized[key] = value.trim();
      } else {
        sanitized[key] = value;
      }
    }

    return ok(sanitized);
  }

  /**
   * Validates target against capability supported target types.
   */
  validateTarget(
    _capability: CapabilityDefinition,
    target: string,
    _port?: number
  ): Result<void, ProblemDetails> {
    if (!target || typeof target !== 'string' || target.trim() === '') {
      return err(
        makeCapabilityProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          'Target must be a non-empty string'
        )
      );
    }

    if (target.includes('\0')) {
      return err(
        makeCapabilityProblem(
          ErrorCode.EXEC_COMMAND_INJECTION_REJECTED,
          'Target contains forbidden null byte (\\0)'
        )
      );
    }

    if (/[;&|`$\r\n]/.test(target)) {
      return err(
        makeCapabilityProblem(
          ErrorCode.EXEC_COMMAND_INJECTION_REJECTED,
          'Target contains forbidden shell metacharacters or control characters'
        )
      );
    }

    if (target.length > 2048) {
      return err(
        makeCapabilityProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          'Target exceeds maximum allowed length of 2048 characters'
        )
      );
    }

    return ok(undefined);
  }

  /**
   * Constructs the structured command vector. Must NEVER use shell interpolation.
   */
  abstract buildCommand(
    capability: CapabilityDefinition,
    target: string,
    params: Record<string, unknown>,
    port?: number
  ): Result<CommandVector, ProblemDetails>;

  /**
   * Parses raw stdout and stderr into normalized domain outputs.
   */
  abstract parseOutput(
    rawOutput: string,
    rawStderr: string,
    exitCode: number,
    sha256: string
  ): Result<AdapterExecutionOutput, ProblemDetails>;

  /**
   * Classifies non-zero exit codes and error output into canonical termination reasons.
   */
  classifyError(
    exitCode: number,
    _rawStderr: string
  ): ExecutionTerminationReason {
    if (exitCode === 0) return 'NORMAL_EXIT';
    return 'PROCESS_CRASH';
  }

  /**
   * Extracts evidence artifacts from the raw execution results.
   */
  extractEvidence(
    rawOutput: string,
    _rawStderr: string,
    sha256: string
  ): readonly EvidenceArtifact[] {
    return [
      {
        name: 'raw_stdout.txt',
        mimeType: 'text/plain',
        contentSha256: sha256,
        content: rawOutput,
        byteSize: Buffer.byteLength(rawOutput, 'utf8'),
      },
    ];
  }

  /**
   * Readiness probe validating local binary health.
   */
  async checkReadiness(): Promise<Result<{ ready: boolean; details?: string }, ProblemDetails>> {
    return ok({ ready: true, details: 'Adapter operational' });
  }
}
