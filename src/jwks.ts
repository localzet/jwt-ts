/*
 * JWKS utilities. Accepts either a JWKS object ({ keys: [...] }) or an array of JWKs.
 * Used for key selection by `kid` and optional `alg` matching.
 */
import { JWK } from './jwk';

export type JWKS = { keys: JWK[] };

export function getJwkByKid(jwks: JWKS | JWK[], kid?: string, alg?: string): JWK | undefined {
    return jwksResolver.getJwkByKid(jwks, kid, alg);
}

export function resolveJwkFromHeader(jwks: JWKS | JWK[], header: { kid?: string; alg?: string }): JWK | undefined {
    return jwksResolver.resolveJwkFromHeader(jwks, header);
}

export class JWKSResolver {
    static getJwkByKid(jwks: JWKS | JWK[], kid?: string, alg?: string) {
        const keys = Array.isArray(jwks) ? jwks : (jwks && jwks.keys) || [];
        if (!kid && !alg) return keys[0];
        let candidates = keys;
        if (kid) candidates = candidates.filter(k => k.kid === kid);
        if (alg) candidates = candidates.filter(k => {
            if (!k.alg) return true;
            return k.alg === alg || k.alg === alg.replace('-', '');
        });
        return candidates[0];
    }

    static resolveJwkFromHeader(jwks: JWKS | JWK[], header: { kid?: string; alg?: string }) {
        return JWKSResolver.getJwkByKid(jwks, header.kid, header.alg);
    }
}

export const jwksResolver = JWKSResolver;
