/*
 * JWT convenience helpers (sign / verify / decode).
 * Implements RFC 7519 (JWT) semantics with JWS integration (RFC 7515).
 */
import { base64urlEncode, base64urlDecode } from './encoding';
import { getSigner, Alg } from './jwa';
import { InvalidSignatureError, TokenExpiredError, NotBeforeError, JWTClaimValidationError, JoseHeaderError } from './errors';
import { jwkToKeyObject, JWK } from './jwk';
import * as crypto from 'crypto';
import { validateJoseHeaders } from './header';

export type JWTPayload = { [key: string]: any };
export type JWTHeader = { alg: Alg; typ?: string; kid?: string;[key: string]: any };

export interface SignOptions {
    alg?: Alg;
    typ?: string;
    kid?: string;
    iat?: boolean; // add issued at
    exp?: number | null; // seconds from now
}

export interface VerifyOptions {
    algorithms?: Alg[];
    issuer?: string | string[];
    subject?: string | string[];
    audience?: string | string[];
    jti?: string;
    typ?: string; // expected typ header
    ignoreExpiration?: boolean;
    clockTolerance?: number; // seconds
}

export async function sign(payload: JWTPayload, key: any, options: SignOptions = {}): Promise<string> {
    return jwtService.sign(payload, key, options);
}

export function decode(token: string, options: { complete?: boolean } = {}): any {
    return jwtService.decode(token, options);
}

export async function verify(token: string, key: any | ((header: JWTHeader) => any | Promise<any>), options: VerifyOptions = {}): Promise<JWTPayload> {
    return jwtService.verify(token, key, options);
}

/**
 * Object-oriented API: JWTService
 * Small wrapper around existing functions to provide a canonical service class.
 */
export class JWTService {
    async sign(payload: JWTPayload, key: any, options: SignOptions = {}): Promise<string> {
        const alg = options.alg || 'HS256';
        const header: JWTHeader = { alg };
        if (options.typ) header.typ = options.typ;
        if (options.kid) header.kid = options.kid;

        try {
            validateJoseHeaders(header, { context: 'jws', expectedTyp: header.typ || null });
        } catch (e) {
            if (e instanceof JoseHeaderError) throw new JWTClaimValidationError(e.message);
            throw e;
        }

        const now = Math.floor(Date.now() / 1000);
        const body: JWTPayload = { ...payload };
        if (options.iat !== false) body.iat = now;
        if (typeof options.exp === 'number') body.exp = now + options.exp;

        const signer = getSigner(alg);
        const encodedHeader = base64urlEncode(JSON.stringify(header));
        const encodedPayload = base64urlEncode(JSON.stringify(body));
        const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`);

        const resolvedKey = this.resolveKeyForSigning(key);
        const signature = await Promise.resolve(signer.sign(signingInput, resolvedKey));
        const sigEnc = base64urlEncode(signature);
        return `${encodedHeader}.${encodedPayload}.${sigEnc}`;
    }

    private resolveKeyForSigning(key: any): crypto.KeyLike | string | Buffer {
        if (!key) return key;
        if (typeof key === 'object' && (key.kty || key.crv)) {
            return jwkToKeyObject(key as JWK);
        }
        return key as any;
    }

    decode(token: string, options: { complete?: boolean } = {}) {
        const parts = token.split('.');
        if (parts.length < 2) throw new JWTClaimValidationError('Invalid token format');
        const header = JSON.parse(base64urlDecode(parts[0]).toString('utf8'));
        const payload = JSON.parse(base64urlDecode(parts[1]).toString('utf8'));
        if (options.complete) return { header, payload, signature: parts[2] ? parts[2] : null };
        return payload;
    }

    async verify(token: string, key: any | ((header: JWTHeader) => any | Promise<any>), options: VerifyOptions = {}): Promise<JWTPayload> {
        const parts = token.split('.');
        if (parts.length !== 3) throw new JWTClaimValidationError('Token must have 3 parts');
        const header = JSON.parse(base64urlDecode(parts[0]).toString('utf8')) as JWTHeader;
        try {
            validateJoseHeaders(header, { context: 'jws', expectedTyp: options.typ || null });
        } catch (e) {
            if (e instanceof JoseHeaderError) throw new JWTClaimValidationError(e.message);
            throw e;
        }
        // An unsecured JWT is never proof of authenticity.
        if (header.alg === 'none') {
            throw new InvalidSignatureError();
        }
        const payload = JSON.parse(base64urlDecode(parts[1]).toString('utf8')) as JWTPayload;

        // Validate registered claim types per RFC 7519
        if (payload.iss !== undefined) {
            if (typeof payload.iss !== 'string') throw new JWTClaimValidationError('iss must be a string');
            if (payload.iss.includes(':')) {
                try { new URL(payload.iss); } catch { throw new JWTClaimValidationError('iss must be a URI when containing ":"'); }
            }
        }
        if (payload.sub !== undefined) {
            if (typeof payload.sub !== 'string') throw new JWTClaimValidationError('sub must be a string');
            if (payload.sub.includes(':')) {
                try { new URL(payload.sub); } catch { throw new JWTClaimValidationError('sub must be a URI when containing ":"'); }
            }
        }
        if (payload.aud !== undefined) {
            const aud = payload.aud;
            if (typeof aud === 'string') {
                // ok
            } else if (Array.isArray(aud)) {
                if (!aud.every(a => typeof a === 'string')) throw new JWTClaimValidationError('aud array values must be strings');
            } else {
                throw new JWTClaimValidationError('aud must be a string or array of strings');
            }
        }

        if (options.algorithms && !options.algorithms.includes(header.alg)) throw new JWTClaimValidationError('Unexpected algorithm');

        if (options.typ) {
            if (header.typ !== options.typ) throw new JWTClaimValidationError('Unexpected typ header');
        }

        const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`);
        const signature = base64urlDecode(parts[2]);
        const signer = getSigner(header.alg);

        let resolvedKey: any;
        if (typeof key === 'function') {
            resolvedKey = await Promise.resolve(key(header));
        } else resolvedKey = key;
        if (typeof resolvedKey === 'object' && (resolvedKey.kty || resolvedKey.crv)) resolvedKey = jwkToKeyObject(resolvedKey as JWK);

        // Only signed tokens may be verified. To inspect unsecured input use decode().
        const ok = await Promise.resolve(signer.verify(signingInput, signature, resolvedKey));
        if (!ok) throw new InvalidSignatureError();

        const now = Math.floor(Date.now() / 1000);
        const tol = options.clockTolerance ?? 0;

        if (!options.ignoreExpiration) {
            if (payload.exp !== undefined) {
                if (typeof payload.exp !== 'number') throw new JWTClaimValidationError('exp must be a number');
                if (now - tol >= payload.exp) throw new TokenExpiredError();
            }
        }

        if (payload.nbf !== undefined) {
            if (typeof payload.nbf !== 'number') throw new JWTClaimValidationError('nbf must be a number');
            if (now + tol < payload.nbf) throw new NotBeforeError();
        }

        if (payload.iat !== undefined) {
            if (typeof payload.iat !== 'number') throw new JWTClaimValidationError('iat must be a number');
            if (now + tol < payload.iat) throw new JWTClaimValidationError('Token issued in the future (iat)');
        }

        if (options.issuer) {
            const iss = payload.iss;
            const okIss = Array.isArray(options.issuer) ? options.issuer.includes(iss) : options.issuer === iss;
            if (!okIss) throw new JWTClaimValidationError('Invalid issuer (iss)');
        }

        if (options.subject) {
            const sub = payload.sub;
            const okSub = Array.isArray(options.subject) ? options.subject.includes(sub) : options.subject === sub;
            if (!okSub) throw new JWTClaimValidationError('Invalid subject (sub)');
        }

        if (options.jti) {
            if (payload.jti !== options.jti) throw new JWTClaimValidationError('Invalid jti');
        }

        if (options.audience) {
            const aud = payload.aud;
            const expected = options.audience;
            if (Array.isArray(expected)) {
                if (typeof aud === 'string') {
                    if (!expected.includes(aud)) throw new JWTClaimValidationError('Invalid audience (aud)');
                } else if (Array.isArray(aud)) {
                    if (!aud.some(a => expected.includes(a))) throw new JWTClaimValidationError('Invalid audience (aud)');
                } else throw new JWTClaimValidationError('Invalid audience (aud)');
            } else {
                if (typeof aud === 'string') {
                    if (aud !== expected) throw new JWTClaimValidationError('Invalid audience (aud)');
                } else if (Array.isArray(aud)) {
                    if (!aud.includes(expected)) throw new JWTClaimValidationError('Invalid audience (aud)');
                } else throw new JWTClaimValidationError('Invalid audience (aud)');
            }
        }

        return payload;
    }
}

export const jwtService = new JWTService();
