/**
 * Shadow : Helix Nebula (SHN) — OpenAPI Specification Controller
 *
 * Serves the authoritative OpenAPI 3.1 contract specification for platform documentation,
 * contract testing, and SDK generation.
 */

import type { IngressRequest, IngressResponse } from '../contracts.js';
import { OPENAPI_3_1_SPEC } from '../openapi/openapi-spec.js';

export class OpenApiController {
  async getSpec(_req: IngressRequest, res: IngressResponse): Promise<void> {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.status(200);
    res.json(OPENAPI_3_1_SPEC);
  }
}
