/**
 * Shadow : Helix Nebula (SHN) — Reference DNS Reconnaissance Tool Adapter
 *
 * Implements capability: shn://capabilities/recon/dns-lookup
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

export class DnsReconAdapter extends BaseToolAdapter {
  readonly adapterId: AdapterId;
  readonly name = 'dns-recon-adapter';
  readonly version = '1.0.0';
  readonly platformSupport: readonly PlatformType[] = ['linux', 'darwin', 'win32'];
  readonly supportedCapabilities: readonly AdapterCapabilityBinding[];

  private readonly executablePath: string;

  constructor(executablePath = 'nslookup') {
    super();
    this.executablePath = executablePath;
    this.adapterId = createAdapterId('adapter:dns-recon').unwrapOr('adapter:dns-recon' as AdapterId);
    this.lifecycleState = 'AVAILABLE';
    this.supportedCapabilities = [
      {
        capabilityId: createCapabilityId('shn://capabilities/recon/dns-lookup').unwrapOr('shn://capabilities/recon/dns-lookup' as any),
        versionConstraint: '^1.0.0',
        supportedTargetTypes: ['DOMAIN', 'HOST', 'IP'],
        priority: 100,
      },
    ];
  }

  override validateTarget(
    capability: CapabilityDefinition,
    target: string,
    port?: number
  ): Result<void, ProblemDetails> {
    const baseRes = super.validateTarget(capability, target, port);
    if (baseRes.isErr) return baseRes;

    const cleanTarget = target.replace(/^https?:\/\//, '').split('/')[0]?.split(':')[0] ?? '';
    if (!cleanTarget || !/^[a-zA-Z0-9.-]+$/.test(cleanTarget)) {
      return err(
        makeCapabilityProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          `Target '${target}' must be a valid domain name or IP address`
        )
      );
    }
    return ok(undefined);
  }

  buildCommand(
    _capability: CapabilityDefinition,
    target: string,
    params: Record<string, unknown>,
    _port?: number
  ): Result<CommandVector, ProblemDetails> {
    const cleanTarget = target.replace(/^https?:\/\//, '').split('/')[0]?.split(':')[0] ?? target;
    const args: string[] = [];

    const recordType = String(params['recordType'] ?? 'A').toUpperCase();
    if (['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'].includes(recordType)) {
      args.push(`-type=${recordType}`);
    }

    args.push(cleanTarget);

    return ok({
      executable: this.executablePath,
      args,
      resourceLimits: {
        timeoutMs: Number(params['timeoutMs'] ?? 10000),
        maxMemoryBytes: 64 * 1024 * 1024,
      },
    });
  }

  parseOutput(
    rawOutput: string,
    rawStderr: string,
    exitCode: number,
    sha256: string
  ): Result<AdapterExecutionOutput, ProblemDetails> {
    const artifacts = this.extractEvidence(rawOutput, rawStderr, sha256);

    const addresses: string[] = [];
    const lines = rawOutput.split(/\r?\n/);
    for (const line of lines) {
      const match = line.match(/Address(?:es)?:\s*([0-9a-fA-F:.]+)/i);
      if (match && match[1] && !match[1].startsWith('127.0.0.1')) {
        addresses.push(match[1].trim());
      }
    }

    return ok({
      exitCode,
      rawOutput,
      rawStderr,
      rawOutputSha256: sha256,
      parsedPayload: {
        resolvedAddresses: Array.from(new Set(addresses)),
        rawText: rawOutput,
      },
      findings: addresses.length > 0 ? [{ type: 'DNS_RESOLVED', addresses }] : [],
      artifacts,
    });
  }

  override extractEvidence(
    rawOutput: string,
    _rawStderr: string,
    sha256: string
  ): readonly EvidenceArtifact[] {
    return [
      {
        name: 'dns_records_raw.txt',
        mimeType: 'text/plain',
        contentSha256: sha256,
        content: rawOutput,
        byteSize: Buffer.byteLength(rawOutput, 'utf8'),
      },
    ];
  }
}
