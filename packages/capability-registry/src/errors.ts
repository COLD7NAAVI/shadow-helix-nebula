/**
 * Shadow : Helix Nebula (SHN) — Capability Registry Problem Details Helper
 */

import {
  createProblemDetails,
  type ErrorCodeType,
  type ProblemDetails,
  type InvalidParam,
  type CreateProblemOptions,
} from '@shn/error-catalog';

export function makeCapabilityProblem(
  errorCode: ErrorCodeType,
  detail: string,
  instance = '/capabilities',
  correlationId = '00000000-0000-7000-8000-000000000000',
  customStatus?: number,
  invalidParams?: readonly InvalidParam[]
): ProblemDetails {
  const options: CreateProblemOptions = {
    errorCode,
    detail,
    instance,
    correlationId,
  };

  if (customStatus !== undefined) {
    options.customStatus = customStatus;
  }
  if (invalidParams !== undefined) {
    options.invalidParams = invalidParams;
  }

  return createProblemDetails(options);
}
