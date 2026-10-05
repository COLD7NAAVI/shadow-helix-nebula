/**
 * Shadow : Helix Nebula (SHN) — Auth & Secrets Problem Details Helper
 */

import {
  createProblemDetails,
  type ErrorCodeType,
  type ProblemDetails,
  type InvalidParam,
  type CreateProblemOptions,
} from '@shn/error-catalog';

export function makeAuthProblem(
  errorCode: ErrorCodeType,
  detail: string,
  instance = '/auth',
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
