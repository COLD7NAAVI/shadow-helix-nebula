/**
 * @shn/error-catalog — Public Facade
 * Enforces MOD-INV-01: Explicit exported contracts only.
 */

export { ErrorCode, type ErrorCodeType } from './codes.js';
export {
  createProblemDetails,
  type CreateProblemOptions,
  type InvalidParam,
  type ProblemDetails,
} from './problem-details.js';
