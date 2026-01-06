/*
 * JWS (JSON Web Signature) helpers — compact and general serialization.
 * Handles protected/unprotected headers, detached payloads (RFC 7797), and basic header validation.
 * Primary reference: RFC 7515.
 */
import { base64urlEncode, base64urlDecode } from './encoding';
import { getSigner, Alg } from './jwa';
import { jwkToKeyObject, JWK } from './jwk';
import { JWTClaimValidationError, InvalidSignatureError, JoseHeaderError } from './errors';
import * as crypto from 'crypto';
import { validateJoseHeaders } from './header';

export type JWSHeader = { alg: Alg; typ?: string; cty?: string; kid?: string; b64?: boolean; crit?: string[];[key: string]: any };

export interface SignerInput {
    key: any; // PEM, KeyObject or JWK
    protectedHeader?: Partial<JWSHeader>;
    header?: { [key: string]: any } | undefined; // unprotected header
}

function resolveKey(key: any): crypto.KeyLike | string | Buffer {
    if (!key) return key;
    if (typeof key === 'object' && (key.kty || key.crv)) return jwkToKeyObject(key as JWK);
    return key as any;
}

export async function signCompact(payload: object | string | Buffer, signer: SignerInput): Promise<string> {
    return jwsService.signCompact(payload, signer);
}

export async function verifyCompact(token: string, keyOrLookup: any | ((header: JWSHeader) => any | Promise<any>), options: { expectedAlg?: Alg; expectedTyp?: string; detachedPayload?: Buffer | string } = {}): Promise<{ header: JWSHeader; payload: any }> {
    return jwsService.verifyCompact(token, keyOrLookup, options);
}

export interface GeneralJWS {
    protected?: { [key: string]: any };
    header?: { [key: string]: any };
    signature: string;
}

export async function signGeneral(payload: object | string | Buffer, signers: SignerInput[], opts: { detached?: boolean } = {}): Promise<{ payload: string; signatures: GeneralJWS[] }> {
    return jwsService.signGeneral(payload, signers, opts);
}

export async function verifyGeneral(obj: { payload: string; signatures: GeneralJWS[] }, keyOrLookup: any | ((header: any) => any | Promise<any>), options: { expectedTyp?: string; detachedPayload?: Buffer | string } = {}): Promise<{ payload: any; verified: boolean }> {
    return jwsService.verifyGeneral(obj, keyOrLookup, options);
}

/**
 * JWSService: class-based API for signing/verifying JWS
 */
export class JWSService {
    async signCompact(payload: object | string | Buffer, signer: SignerInput) {
        const header: JWSHeader = { alg: (signer.protectedHeader && (signer.protectedHeader.alg as Alg)) || 'HS256' };
        if (signer.protectedHeader) Object.assign(header, signer.protectedHeader);

        // validate header strictly
        try {
            validateJoseHeaders(header, { context: 'jws', allowedExtensions: new Set(['b64']), expectedTyp: header.typ || null });
        } catch (e) {
            if (e instanceof JoseHeaderError) throw new JWTClaimValidationError(e.message);
            throw e;
        }

        // RFC 7797: if b64 is false, it MUST be listed in crit
        const b64 = header.hasOwnProperty('b64') ? header.b64 !== false : true;
        if (header.b64 === false) {
            const crit = header.crit as string[] | undefined;
            if (!Array.isArray(crit) || !crit.includes('b64')) throw new JWTClaimValidationError('When using b64=false, header must include "b64" in "crit"');
        }

        const encodedHeader = base64urlEncode(JSON.stringify(header));
        const payloadBuf = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : Buffer.isBuffer(payload) ? payload : Buffer.from(JSON.stringify(payload), 'utf8');

        const s = getSigner(header.alg);
        const resolved = resolveKey(signer.key);

        if (b64) {
            const encodedPayload = base64urlEncode(payloadBuf);
            const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`);
            const sig = await Promise.resolve(s.sign(signingInput, resolved));
            const sigEnc = base64urlEncode(sig);
            return `${encodedHeader}.${encodedPayload}.${sigEnc}`;
        } else {
            const headerDot = Buffer.from(encodedHeader + '.', 'ascii');
            const signingInput = Buffer.concat([headerDot, payloadBuf]);
            const sig = await Promise.resolve(s.sign(signingInput, resolved));
            const sigEnc = base64urlEncode(sig);
            return `${encodedHeader}..${sigEnc}`;
        }
    }

    async verifyCompact(token: string, keyOrLookup: any | ((header: JWSHeader) => any | Promise<any>), options: { expectedAlg?: Alg; expectedTyp?: string; detachedPayload?: Buffer | string } = {}) {
        const parts = token.split('.');
        if (parts.length !== 3) throw new JWTClaimValidationError('JWS Compact Serialization must have three parts');
        const header = JSON.parse(base64urlDecode(parts[0]).toString('utf8')) as JWSHeader;
        try {
            validateJoseHeaders(header, { context: 'jws', allowedExtensions: new Set(['b64']), expectedTyp: options.expectedTyp ?? null });
        } catch (e) {
            if (e instanceof JoseHeaderError) throw new JWTClaimValidationError(e.message);
            throw e;
        }
        if (options.expectedAlg && header.alg !== options.expectedAlg) throw new JWTClaimValidationError('Unexpected alg');
        if (options.expectedTyp && header.typ !== options.expectedTyp) throw new JWTClaimValidationError('Unexpected typ');

        if (Array.isArray(header.crit)) {
            for (const c of header.crit) {
                if (c !== 'b64') throw new JWTClaimValidationError(`Unsupported critical header ${c}`);
                if (!header.hasOwnProperty('b64')) throw new JWTClaimValidationError('crit declares b64 but b64 header missing');
            }
        }

        let key: any;
        if (typeof keyOrLookup === 'function') {
            key = await Promise.resolve(keyOrLookup(header));
        } else key = keyOrLookup;
        const resolved = resolveKey(key);

        const b64 = header.hasOwnProperty('b64') ? header.b64 !== false : true;

        const signer = getSigner(header.alg);
        if (b64) {
            const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`);
            const signature = base64urlDecode(parts[2]);
            const ok = await Promise.resolve(signer.verify(signingInput, signature, resolved));
            if (!ok) throw new InvalidSignatureError();
            const payload = JSON.parse(base64urlDecode(parts[1]).toString('utf8'));
            return { header, payload };
        } else {
            if (!options.detachedPayload) throw new JWTClaimValidationError('Detached payload required for b64=false');
            const payloadBuf = typeof options.detachedPayload === 'string' ? Buffer.from(options.detachedPayload, 'utf8') : options.detachedPayload as Buffer;
            const headerDot = Buffer.from(parts[0] + '.', 'ascii');
            const signingInput = Buffer.concat([headerDot, payloadBuf]);
            const signature = base64urlDecode(parts[2]);
            const ok = await Promise.resolve(signer.verify(signingInput, signature, resolved));
            if (!ok) throw new InvalidSignatureError();
            try {
                return { header, payload: JSON.parse(payloadBuf.toString('utf8')) };
            } catch (e) {
                return { header, payload: payloadBuf };
            }
        }
    }

    async signGeneral(payload: object | string | Buffer, signers: SignerInput[], opts: { detached?: boolean } = {}) {
        const payloadBuf = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : Buffer.isBuffer(payload) ? payload : Buffer.from(JSON.stringify(payload), 'utf8');
        const encodedPayload = opts.detached ? '' : base64urlEncode(payloadBuf);
        const signatures: GeneralJWS[] = [];

        for (const sInput of signers) {
            const prot = (sInput.protectedHeader && { ...sInput.protectedHeader }) || { alg: 'HS256' } as any;
            try {
                validateJoseHeaders(prot, { context: 'jws', allowedExtensions: new Set(['b64']), expectedTyp: prot.typ || null });
            } catch (e) {
                if (e instanceof JoseHeaderError) throw new JWTClaimValidationError(e.message);
                throw e;
            }
            const encodedProt = base64urlEncode(JSON.stringify(prot));
            const signingInput = opts.detached ? Buffer.concat([Buffer.from(encodedProt + '.', 'ascii'), payloadBuf]) : Buffer.from(`${encodedProt}.${encodedPayload}`);
            const s = getSigner(prot.alg as Alg);
            const resolved = resolveKey(sInput.key);
            const sig = await Promise.resolve(s.sign(signingInput, resolved));
            signatures.push({ protected: prot, header: sInput.header, signature: base64urlEncode(sig) });
        }

        return { payload: encodedPayload, signatures };
    }

    async verifyGeneral(obj: { payload: string; signatures: GeneralJWS[] }, keyOrLookup: any | ((header: any) => any | Promise<any>), options: { expectedTyp?: string; detachedPayload?: Buffer | string } = {}) {
        const payloadBuf = options.detachedPayload ? (typeof options.detachedPayload === 'string' ? Buffer.from(options.detachedPayload, 'utf8') : options.detachedPayload as Buffer) : base64urlDecode(obj.payload);
        const payload = (() => {
            try { return JSON.parse(payloadBuf.toString('utf8')); } catch { return payloadBuf; }
        })();
        for (const sig of obj.signatures) {
            const prot = sig.protected || {};
            const merged = Object.assign({}, prot, sig.header || {});
            try {
                validateJoseHeaders(merged, { context: 'jws', enforceUnknown: 'reject', allowedExtensions: new Set(['b64']), expectedTyp: options.expectedTyp ?? null });
            } catch (e) {
                if (e instanceof JoseHeaderError) throw new JWTClaimValidationError(e.message);
                throw e;
            }

            // Determine algorithm from merged header (protected overrides unprotected)
            const alg = merged.alg as string | undefined;
            if (alg === 'none') {
                if (sig.signature && sig.signature !== '') throw new InvalidSignatureError();
                continue;
            }

            const encodedProt = base64urlEncode(JSON.stringify(prot));
            const signingInput = options.detachedPayload ? Buffer.concat([Buffer.from(encodedProt + '.', 'ascii'), payloadBuf]) : Buffer.from(`${encodedProt}.${obj.payload}`);
            let key: any;
            if (typeof keyOrLookup === 'function') key = await Promise.resolve(keyOrLookup(merged));
            else key = keyOrLookup;
            const resolved = resolveKey(key);
            const signer = getSigner(alg as Alg);
            const ok = await Promise.resolve(signer.verify(signingInput, base64urlDecode(sig.signature), resolved));
            if (!ok) throw new InvalidSignatureError();
        }
        return { payload, verified: true };
    }
}

export const jwsService = new JWSService();
