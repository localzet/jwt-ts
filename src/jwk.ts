/*
 * JWK utilities (RFC 7517) and thumbprint (RFC 7638).
 * Conversions between Node.js KeyObject, PEM and JWK representations.
 */
import * as crypto from 'crypto';

export type JWK = { [key: string]: any };

/** Create a KeyObject from a JWK. Supports RSA, EC and OKP. */
export function jwkToKeyObject(jwk: JWK): crypto.KeyObject {
    return jwkManager.jwkToKeyObject(jwk);
}

export function keyObjectToJwk(key: crypto.KeyObject): JWK {
    return jwkManager.keyObjectToJwk(key);
}

export function jwkToPEM(jwk: JWK, opts: { private?: boolean } = {}): string {
    return jwkManager.jwkToPEM(jwk, opts);
}

export function pemToJwk(pem: string): JWK {
    return jwkManager.pemToJwk(pem);
}

export function jwkThumbprint(jwk: JWK, hash = 'sha256'): string {
    return jwkManager.jwkThumbprint(jwk, hash);
}

/**
 * JWKManager: convenience class wrapper for JWK operations
 */
export class JWKManager {
    jwkToKeyObject(jwk: JWK) {
        if (!jwk || typeof jwk !== 'object') throw new TypeError('Invalid JWK');
        const hasPrivate = !!jwk.d;
        try {
            if (hasPrivate) return crypto.createPrivateKey({ key: jwk as any, format: 'jwk' });
            return crypto.createPublicKey({ key: jwk as any, format: 'jwk' });
        } catch (e) {
            throw new Error('Failed to convert JWK to KeyObject: ' + (e as Error).message);
        }
    }

    keyObjectToJwk(key: crypto.KeyObject) {
        try {
            return key.export({ format: 'jwk' }) as JWK;
        } catch (e) {
            throw new Error('Failed to export KeyObject to JWK: ' + (e as Error).message);
        }
    }

    jwkToPEM(jwk: JWK, opts: { private?: boolean } = {}) {
        const keyObj = this.jwkToKeyObject(jwk);
        if (opts.private) return keyObj.export({ type: 'pkcs8', format: 'pem' }) as string;
        return keyObj.export({ type: 'spki', format: 'pem' }) as string;
    }

    pemToJwk(pem: string) {
        const keyObj = crypto.createPublicKey(pem);
        try {
            return keyObj.export({ format: 'jwk' }) as JWK;
        } catch (e) {
            const priv = crypto.createPrivateKey(pem);
            return priv.export({ format: 'jwk' }) as JWK;
        }
    }

    jwkThumbprint(jwk: JWK, hash = 'sha256') {
        const kty = jwk.kty;
        let members: string[] = [];
        if (kty === 'RSA') members = ['e', 'kty', 'n'];
        else if (kty === 'EC') members = ['crv', 'kty', 'x', 'y'];
        else if (kty === 'OKP') members = ['crv', 'kty', 'x'];
        else throw new Error('Unsupported JWK kty for thumbprint');
        const obj: any = {};
        for (const m of members) obj[m] = jwk[m];
        const json = JSON.stringify(obj);
        const h = crypto.createHash(hash).update(json).digest();
        return h.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    }
}

export const jwkManager = new JWKManager();
