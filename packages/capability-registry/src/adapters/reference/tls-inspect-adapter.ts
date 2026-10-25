/**
 * Shadow : Helix Nebula (SHN) — Reference TLS/SSL Inspection Tool Adapter
 *
 * Implements capability: shn://capabilities/web/tls-inspect
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

export class TlsInspectAdapter extends BaseToolAdapter {
  readonly adapterId: AdapterId;
  readonly name = 'tls-inspect-adapter';
  readonly version = '1.0.0';
  readonly platformSupport: readonly PlatformType[] = ['linux', 'darwin', 'win32'];
  readonly supportedCapabilities: readonly AdapterCapabilityBinding[];

  private readonly executablePath: string;

  constructor(executablePath = 'curl') {
    super();
    this.executablePath = executablePath;
    this.adapterId = createAdapterId('adapter:tls-inspect').unwrapOr('adapter:tls-inspect' as AdapterId);
    this.lifecycleState = 'AVAILABLE';
    this.supportedCapabilities = [
      {
        capabilityId: createCapabilityId('shn://capabilities/web/tls-inspect').unwrapOr('shn://capabilities/web/tls-inspect' as any),
        versionConstraint: '^1.0.0',
        supportedTargetTypes: ['URL', 'DOMAIN', 'HOST'],
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

    if (!target.startsWith('https://') && !/^[a-zA-Z0-9.-]+$/.test(target)) {
      return err(
        makeCapabilityProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          `Target '${target}' must be an HTTPS URL or domain hostname`
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
    const args: string[] = ['-sIv', '--connect-timeout', '10'];

    const targetUrl = target.startsWith('https://') ? target : `https://${target}`;
    args.push(targetUrl);

    return ok({
      executable: this.executablePath,
      args,
      resourceLimits: {
        timeoutMs: Number(params['timeoutMs'] ?? 15000),
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
    const combined = `${rawOutput}\n${rawStderr}`;
    const artifacts = this.extractEvidence(rawOutput, rawStderr, sha256);

    const isSecure = combined.includes('SSL certificate verify ok') || combined.includes('TLSv1.3') || combined.includes('TLSv1.2');
    const issuerMatch = /issuer:\s*(.+)/i.exec(combined);
    const subjectMatch = /subject:\s*(.+)/i.exec(combined);
    const expireMatch = /expire date:\s*(.+)/i.exec(combined);
    const protocolMatch = /SSL connection using (.+)/i.exec(combined);

    const parsedPayload = {
      isSecure,
      protocol: protocolMatch?.[1]?.trim() ?? 'TLS',
      issuer: issuerMatch?.[1]?.trim() ?? 'Unknown',
      subject: subjectMatch?.[1]?.trim() ?? 'Unknown',
      expiresAt: expireMatch?.[1]?.trim() ?? null,
    };

    return ok({
      exitCode,
      rawOutput,
      rawStderr,
      rawOutputSha256: sha256,
      parsedPayload,
      findings: isSecure ? [{ type: 'TLS_VERIFIED', protocol: parsedPayload.protocol }] : [],
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
        name: 'tls_handshake_raw.txt',
        mimeType: 'text/plain',
        contentSha256: sha256,
        content: rawOutput,
        byteSize: Buffer.byteLength(rawOutput, 'utf8'),
      },
    ];
  }
}
