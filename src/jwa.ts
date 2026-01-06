/*
 * JWA (JSON Web Algorithms) helpers - signer factory and algorithm implementations.
 * Implements HMAC, RSA, RSA-PSS, ECDSA (incl. secp256k1), and EdDSA where supported.
 * See RFC 7518 for algorithm semantics and RFC 8037 for EdDSA.
 */
import * as crypto from 'crypto';
import { derToJose, joseToDer } from './encoding';

export type Alg =
    | 'HS256' | 'HS384' | 'HS512'
    | 'RS256' | 'RS384' | 'RS512'
    | 'PS256' | 'PS384' | 'PS512'
    | 'ES256' | 'ES256K' | 'ES384' | 'ES512'
    | 'EdDSA'
    | 'none';

export interface Signer {
    sign(payload: Buffer, key: crypto.KeyLike | Buffer | string): Buffer | Promise<Buffer>;
    verify(payload: Buffer, signature: Buffer, key: crypto.KeyLike | Buffer | string): boolean | Promise<boolean>;
}

const HMAC = (hash: string): Signer => ({
    sign(payload: Buffer, key) {
        const h = crypto.createHmac(hash, key as crypto.BinaryLike);
        h.update(payload);
        return h.digest();
    },
    verify(payload: Buffer, signature: Buffer, key) {
        const sig = (this.sign as any)(payload, key) as Buffer;
        return crypto.timingSafeEqual(sig, signature);
    }
});

const RSA = (hash: string, padding = crypto.constants.RSA_PKCS1_PADDING): Signer => ({
    sign(payload: Buffer, key) {
        const s = crypto.createSign(hash);
        s.update(payload);
        s.end();
        return s.sign({ key: key as crypto.KeyLike, padding } as any) as Buffer;
    },
    verify(payload: Buffer, signature: Buffer, key) {
        const v = crypto.createVerify(hash);
        v.update(payload);
        v.end();
        return v.verify(key as crypto.KeyLike, signature) as boolean;
    }
});

const RSA_PSS = (hash: string): Signer => ({
    sign(payload: Buffer, key) {
        const s = crypto.createSign(hash);
        s.update(payload);
        s.end();
        return s.sign({ key: key as crypto.KeyLike, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST } as any) as Buffer;
    },
    verify(payload: Buffer, signature: Buffer, key) {
        const v = crypto.createVerify(hash);
        v.update(payload);
        v.end();
        return v.verify({ key: key as crypto.KeyLike, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST } as any, signature) as boolean;
    }
});

const ECDSA = (hash: string, keySize: number): Signer => ({
    sign(payload: Buffer, key) {
        const s = crypto.createSign(hash);
        s.update(payload);
        s.end();
        const der = s.sign(key as crypto.KeyLike) as Buffer;
        return derToJose(der, keySize);
    },
    verify(payload: Buffer, signature: Buffer, key) {
        const der = joseToDer(signature);
        const v = crypto.createVerify(hash);
        v.update(payload);
        v.end();
        return v.verify(key as crypto.KeyLike, der) as boolean;
    }
});

export function getSigner(alg: Alg): Signer {
    return JWAFactory.getSigner(alg);
}

/**
 * JWAFactory: class wrapper exposing algorithm factory
 */
export class JWAFactory {
    static getSigner(alg: Alg): Signer {
        switch (alg) {
            case 'HS256': return HMAC('sha256');
            case 'HS384': return HMAC('sha384');
            case 'HS512': return HMAC('sha512');

            case 'RS256': return RSA('sha256', crypto.constants.RSA_PKCS1_PADDING);
            case 'RS384': return RSA('sha384', crypto.constants.RSA_PKCS1_PADDING);
            case 'RS512': return RSA('sha512', crypto.constants.RSA_PKCS1_PADDING);

            case 'PS256': return RSA_PSS('sha256');
            case 'PS384': return RSA_PSS('sha384');
            case 'PS512': return RSA_PSS('sha512');

            case 'ES256': return ECDSA('sha256', 256);
            case 'ES256K': return ECDSA('sha256', 256); // secp256k1
            case 'ES384': return ECDSA('sha384', 384);
            case 'ES512': return ECDSA('sha512', 521);

            case 'EdDSA':
                return {
                    sign(payload: Buffer, key) {
                        return (crypto as any).sign(null, payload, key as crypto.KeyLike) as Buffer;
                    },
                    verify(payload: Buffer, signature: Buffer, key) {
                        return (crypto as any).verify(null, payload, key as crypto.KeyLike, signature) as boolean;
                    }
                };

            case 'none':
                return {
                    sign() { return Buffer.alloc(0); },
                    verify() { return true; }
                };

            default:
                throw new Error(`Unsupported alg ${alg}`);
        }
    }
}

export const jwa = JWAFactory;
