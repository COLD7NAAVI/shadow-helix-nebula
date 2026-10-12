/**
 * Shadow : Helix Nebula (SHN) — Ingress HTTP Router
 *
 * Authoritative Spec: Phase 0.14 Sections 7 & 8 (Level 2/3 REST, Path Mapping).
 * High-performance route matching with route parameters and layered middleware chains.
 */

import {
  ErrorCode,
  createProblemDetails,
} from '@shn/error-catalog';
import type {
  IngressRequest,
  IngressResponse,
  RouteHandler,
  Middleware,
} from '../contracts.js';
import { sendProblemDetails, handleUnhandledError } from '../errors/problem-details-filter.js';

interface RouteDefinition {
  method: string;
  pathPattern: string;
  regex: RegExp;
  paramNames: string[];
  middlewares: Middleware[];
  handler: RouteHandler;
}

export class Router {
  private readonly routes: RouteDefinition[] = [];
  private readonly globalMiddlewares: Middleware[] = [];

  use(middleware: Middleware): this {
    this.globalMiddlewares.push(middleware);
    return this;
  }

  get(pathPattern: string, ...handlers: [...Middleware[], RouteHandler]): this {
    return this.addRoute('GET', pathPattern, handlers);
  }

  post(pathPattern: string, ...handlers: [...Middleware[], RouteHandler]): this {
    return this.addRoute('POST', pathPattern, handlers);
  }

  put(pathPattern: string, ...handlers: [...Middleware[], RouteHandler]): this {
    return this.addRoute('PUT', pathPattern, handlers);
  }

  patch(pathPattern: string, ...handlers: [...Middleware[], RouteHandler]): this {
    return this.addRoute('PATCH', pathPattern, handlers);
  }

  delete(pathPattern: string, ...handlers: [...Middleware[], RouteHandler]): this {
    return this.addRoute('DELETE', pathPattern, handlers);
  }

  options(pathPattern: string, ...handlers: [...Middleware[], RouteHandler]): this {
    return this.addRoute('OPTIONS', pathPattern, handlers);
  }

  private addRoute(
    method: string,
    pathPattern: string,
    handlers: [...Middleware[], RouteHandler]
  ): this {
    const handler = handlers.pop() as RouteHandler;
    const middlewares = handlers as Middleware[];

    const paramNames: string[] = [];
    const regexSource = pathPattern
      .replace(/:([a-zA-Z0-9_]+)/g, (_, name) => {
        paramNames.push(name);
        return '([^\\/]+)';
      })
      .replace(/\//g, '\\/');

    const regex = new RegExp(`^${regexSource}$`);

    this.routes.push({
      method: method.toUpperCase(),
      pathPattern,
      regex,
      paramNames,
      middlewares,
      handler,
    });

    return this;
  }

  async handle(req: IngressRequest, res: IngressResponse): Promise<void> {
    try {
      // Execute global middlewares first
      let routeMatch: { route: RouteDefinition; params: Record<string, string> } | null = null;

      for (const r of this.routes) {
        if (r.method === req.method || (req.method === 'HEAD' && r.method === 'GET')) {
          const match = r.regex.exec(req.path);
          if (match) {
            const params: Record<string, string> = {};
            for (let i = 0; i < r.paramNames.length; i++) {
              const name = r.paramNames[i];
              const val = match[i + 1];
              if (name && val !== undefined) {
                params[name] = decodeURIComponent(val);
              }
            }
            routeMatch = { route: r, params };
            break;
          }
        }
      }

      if (routeMatch) {
        req.params = routeMatch.params;
      }

      // Build execution pipeline: global middlewares -> route middlewares -> route handler
      const pipeline: Middleware[] = [...this.globalMiddlewares];

      if (routeMatch) {
        pipeline.push(...routeMatch.route.middlewares);
        pipeline.push(async (rReq, rRes) => {
          await routeMatch.route.handler(rReq, rRes);
        });
      } else {
        pipeline.push(async (_rReq, rRes) => {
          // If OPTIONS preflight without specific handler, return 204 with CORS
          if (req.method === 'OPTIONS') {
            rRes
              .status(204)
              .setHeader('Access-Control-Allow-Origin', '*')
              .setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
              .setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Correlation-ID, X-Request-ID')
              .empty();
            return;
          }

          const problem = createProblemDetails({
            errorCode: ErrorCode.STORAGE_NOT_FOUND,
            detail: `Resource endpoint "${req.method} ${req.path}" was not found.`,
            instance: req.path,
            correlationId: req.correlationId,
            customStatus: 404,
          });
          sendProblemDetails(rRes, problem);
        });
      }

      // Run middleware pipeline
      let index = 0;
      const next = async (): Promise<void> => {
        if (index < pipeline.length) {
          const fn = pipeline[index++];
          if (fn) {
            await fn(req, res, next);
          }
        }
      };

      await next();
    } catch (err: unknown) {
      handleUnhandledError(err, req, res);
    }
  }
}
