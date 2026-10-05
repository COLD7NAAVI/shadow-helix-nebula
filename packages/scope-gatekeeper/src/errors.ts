/**
 * Shadow : Helix Nebula (SHN) — Scope Gatekeeper Problem Details Helper
 */

import {
  createProblemDetails,
  type ErrorCodeType,
  type ProblemDetails,
  type InvalidParam,
  type CreateProblemOptions,
} from '@shn/error-catalog';

export function makeScopeProblem(
  errorCode: ErrorCodeType,
  detail: string,
  instance = '/scope',
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
