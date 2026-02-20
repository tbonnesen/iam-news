import type { FastifyReply, FastifyRequest, preHandlerHookHandler } from 'fastify';
import { jwtVerify } from 'jose';
import type { AppConfig } from '../config.js';
import type { AuthContext } from '../domain/types.js';

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthContext;
  }
}

function unauthorized(reply: FastifyReply, message = 'Unauthorized'): never {
  void reply.code(401).send({ error: message });
  throw new Error(message);
}

function forbidden(reply: FastifyReply, message = 'Forbidden'): never {
  void reply.code(403).send({ error: message });
  throw new Error(message);
}

export function requireRoles(config: AppConfig, requiredRoles: string[]): preHandlerHookHandler {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const authorization = request.headers.authorization;
    if (!authorization || !authorization.startsWith('Bearer ')) {
      unauthorized(reply);
    }

    const token = authorization.slice('Bearer '.length).trim();
    if (!token) {
      unauthorized(reply);
    }

    const key = new TextEncoder().encode(config.jwtSecret);

    try {
      const verified = await jwtVerify(token, key, {
        issuer: config.jwtIssuer,
        audience: config.jwtAudience,
        algorithms: ['HS256']
      });

      const rolesClaim = verified.payload.roles;
      const roles = Array.isArray(rolesClaim)
        ? rolesClaim.filter((item): item is string => typeof item === 'string')
        : [];

      if (roles.length === 0 || !requiredRoles.every((role) => roles.includes(role))) {
        forbidden(reply);
      }

      request.auth = {
        sub: typeof verified.payload.sub === 'string' ? verified.payload.sub : 'unknown',
        roles
      };
    } catch {
      unauthorized(reply);
    }
  };
}
