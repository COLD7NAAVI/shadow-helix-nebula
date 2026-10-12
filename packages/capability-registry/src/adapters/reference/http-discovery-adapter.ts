/**
 * Shadow : Helix Nebula (SHN) — Reference HTTP Discovery Tool Adapter
 *
 * Implements abstract capability: shn://capabilities/web/http-discovery
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

export class HttpDiscoveryAdapter extends BaseToolAdapter {
  readonly adapterId: AdapterId;
  readonly name = 'http-discovery-adapter';
  readonly version = '1.0.0';
  readonly platformSupport: readonly PlatformType[] = ['linux', 'darwin', 'win32'];
  readonly supportedCapabilities: readonly AdapterCapabilityBinding[];

  private readonly executablePath: string;

  constructor(executablePath = 'curl') {
    super();
    this.executablePath = executablePath;
    this.adapterId = createAdapterId('adapter:http-discovery').unwrapOr('adapter:http-discovery' as AdapterId);
    this.lifecycleState = 'AVAILABLE';
    this.supportedCapabilities = [
      {
        capabilityId: createCapabilityId('shn://capabilities/web/http-discovery').unwrapOr('shn://capabilities/web/http-discovery' as any),
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

    // HTTP discovery requires http:// or https:// or plain hostname
    if (!target.startsWith('http://') && !target.startsWith('https://') && !/^[a-zA-Z0-9.-]+$/.test(target)) {
      return err(
        makeCapabilityProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          `Target '${target}' must be a valid HTTP/HTTPS URL or domain`
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
    const args: string[] = ['-s', '-S', '-I'];

    const followRedirects = params['followRedirects'] !== false;
    if (followRedirects) {
      args.push('-L');
    }

    const maxTime = Math.min(Math.max(Number(params['timeoutSeconds'] ?? 10), 1), 60);
    args.push('--max-time', String(maxTime));

    // User agent
    const userAgent = String(params['userAgent'] ?? 'SHN-Security-Scanner/1.0');
    if (userAgent.includes('\0') || userAgent.length > 256) {
      return err(
        makeCapabilityProblem(
          ErrorCode.INVALID_PAYLOAD_SCHEMA,
          'Invalid userAgent parameter'
        )
      );
    }
    args.push('-A', userAgent);

    // Target URL
    const url = target.startsWith('http://') || target.startsWith('https://')
      ? target
      : `https://${target}`;
    args.push(url);

    return ok({
      executable: this.executablePath,
      args,
      resourceLimits: {
        timeoutMs: (maxTime + 5) * 1000,
      },
    });
  }

  parseOutput(
    rawOutput: string,
    rawStderr: string,
    exitCode: number,
    sha256: string
  ): Result<AdapterExecutionOutput, ProblemDetails> {
    const headers: Record<string, string> = {};
    let statusCode = 0;

    const lines = rawOutput.split(/\r?\n/);
    for (const line of lines) {
      const statusMatch = /^HTTP\/[12](\.[01])?\s+(\d{3})/i.exec(line);
      if (statusMatch) {
        statusCode = parseInt(statusMatch[2]!, 10);
        continue;
      }

      const headerMatch = /^([a-zA-Z0-9_-]+):\s*(.*)$/.exec(line);
      if (headerMatch) {
        headers[headerMatch[1]!.toLowerCase()] = headerMatch[2]!.trim();
      }
    }

    const artifacts = this.extractEvidence(rawOutput, rawStderr, sha256);

    return ok({
      exitCode,
      rawOutput,
      rawStderr,
      rawOutputSha256: sha256,
      parsedPayload: {
        statusCode,
        server: headers['server'],
        contentType: headers['content-type'],
        headers,
      },
      findings: statusCode > 0 ? [{ type: 'HTTP_SERVICE', statusCode, server: headers['server'] }] : [],
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
        name: 'http_headers_raw.txt',
        mimeType: 'text/plain',
        contentSha256: sha256,
        content: rawOutput,
        byteSize: Buffer.byteLength(rawOutput, 'utf8'),
      },
    ];
  }
}
