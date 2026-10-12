/**
 * Shadow : Helix Nebula (SHN) — Reference Network Port Scan Tool Adapter
 *
 * Implements abstract capability: shn://capabilities/network/port-scan
 */

import {
  ok,
  err,
  createAdapterId,
  createCapabilityId,
  type Result,
  type AdapterId,
} from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';
import { makeCapabilityProblem } from '../../errors.js';
import { BaseToolAdapter } from '../base-tool-adapter.js';
import type {
  CapabilityDefinition,
  CommandVector,
  AdapterExecutionOutput,
  EvidenceArtifact,
  PlatformType,
  AdapterCapabilityBinding,
} from '../../contracts.js';

export class NetworkPortScanAdapter extends BaseToolAdapter {
  readonly adapterId: AdapterId;
  readonly name = 'network-port-scan-adapter';
  readonly version = '1.0.0';
  readonly platformSupport: readonly PlatformType[] = ['linux', 'darwin', 'win32'];
  readonly supportedCapabilities: readonly AdapterCapabilityBinding[];

  private readonly executablePath: string;

  constructor(executablePath = 'nmap') {
    super();
    this.executablePath = executablePath;
    this.adapterId = createAdapterId('adapter:network-port-scan').unwrapOr('adapter:network-port-scan' as AdapterId);
    this.lifecycleState = 'AVAILABLE';
    this.supportedCapabilities = [
      {
        capabilityId: createCapabilityId('shn://capabilities/network/port-scan').unwrapOr('shn://capabilities/network/port-scan' as any),
        versionConstraint: '^1.0.0',
        supportedTargetTypes: ['IP', 'CIDR', 'DOMAIN', 'HOST'],
        priority: 100,
      },
    ];
  }

  buildCommand(
    _capability: CapabilityDefinition,
    target: string,
    params: Record<string, unknown>,
    port?: number
  ): Result<CommandVector, ProblemDetails> {
    const args: string[] = [];

    // Timing template
    const timing = Number(params['timing'] ?? 3);
    if (timing < 0 || timing > 5) {
      return err(
        makeCapabilityProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          'Timing template must be between 0 and 5'
        )
      );
    }
    args.push(`-T${timing}`);

    // Ports specification
    if (port) {
      args.push('-p', String(port));
    } else if (params['ports']) {
      const portSpec = String(params['ports']);
      // Allow only digits, commas, and dashes
      if (!/^[0-9,-]+$/.test(portSpec)) {
        return err(
          makeCapabilityProblem(
            ErrorCode.INVALID_PAYLOAD_SCHEMA,
            'Ports specification must contain only digits, commas, and hyphens'
          )
        );
      }
      args.push('-p', portSpec);
    } else {
      args.push('--top-ports', '100');
    }

    // Connect scan by default (non-privileged)
    args.push('-sT');

    // Add target as final argument
    args.push(target);

    return ok({
      executable: this.executablePath,
      args,
      resourceLimits: {
        timeoutMs: Number(params['timeoutMs'] ?? 30_000),
      },
    });
  }

  parseOutput(
    rawOutput: string,
    rawStderr: string,
    exitCode: number,
    sha256: string
  ): Result<AdapterExecutionOutput, ProblemDetails> {
    const findings: Array<{ port: number; protocol: string; state: string; service?: string }> = [];

    // Parse simple line format (e.g., "80/tcp open http" or custom mocked output)
    const lines = rawOutput.split(/\r?\n/);
    for (const line of lines) {
      const match = /(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s*(\S*)/i.exec(line);
      if (match) {
        findings.push({
          port: parseInt(match[1]!, 10),
          protocol: match[2]!.toLowerCase(),
          state: match[3]!.toLowerCase(),
          ...(match[4] ? { service: match[4] } : {}),
        });
      }
    }

    const artifacts = this.extractEvidence(rawOutput, rawStderr, sha256);

    return ok({
      exitCode,
      rawOutput,
      rawStderr,
      rawOutputSha256: sha256,
      parsedPayload: {
        totalPortsFound: findings.length,
        openPorts: findings.filter(f => f.state === 'open'),
      },
      findings,
      artifacts,
    });
  }

  override extractEvidence(
    rawOutput: string,
    _rawStderr: string,
    sha256: string
  ): readonly EvidenceArtifact[] {
    const textArtifact: EvidenceArtifact = {
      name: 'port_scan_raw.txt',
      mimeType: 'text/plain',
      contentSha256: sha256,
      content: rawOutput,
      byteSize: Buffer.byteLength(rawOutput, 'utf8'),
    };

    return [textArtifact];
  }
}
