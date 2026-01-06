/*
 * JWE (JSON Web Encryption) helpers.
 * Implements compact and general JSON serializations with common algorithms:
 * AES-GCM content encryption, RSA-OAEP/RSA1_5, AES Key Wrap (RFC 3394), and ECDH-ES flows.
 * See RFC 7516 (JWE) and RFC 7518 (JWA) for details.
 */
import * as crypto from 'crypto';
import { base64urlEncode, base64urlDecode } from './encoding';
import { jwkToKeyObject, JWK } from './jwk';
import { resolveJwkFromHeader } from './jwks';
import { JWTClaimValidationError, JoseHeaderError } from './errors';
import { validateJoseHeaders } from './header';

type KeyLike = crypto.KeyLike | string | Buffer;

function resolveKey(key: any): KeyLike | undefined {
    if (!key) return undefined;
    if (typeof key === 'object' && (key.kty || key.crv || key.k)) {
        // symmetric JWK with k (base64url) or RSA/EC JWK
        if (key.k) return Buffer.from(base64urlDecode(key.k));
        return jwkToKeyObject(key as JWK);
    }
    return key as KeyLike;
}

function rand(bytes: number) {
    return crypto.randomBytes(bytes);
}

function aesGcmEncrypt(cek: Buffer, iv: Buffer, plaintext: Buffer, aad: Buffer) {
    const algorithm = cek.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
    const cipher = crypto.createCipheriv(algorithm, cek, iv, { authTagLength: 16 });
    if (aad) cipher.setAAD(aad);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { ciphertext: ct, tag };
}

function aesGcmDecrypt(cek: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer, aad: Buffer) {
    const algorithm = cek.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
    const decipher = crypto.createDecipheriv(algorithm, cek, iv, { authTagLength: 16 });
    if (aad) decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return pt;
}

// AES-CBC with HMAC (composite AE) per RFC 7518 (A128CBC-HS256, A256CBC-HS512)
function aesCbcHmacEncrypt(cek: Buffer, iv: Buffer, plaintext: Buffer, aad: Buffer, alg: string) {
    // CEK is split: MAC key (left half) | ENC key (right half)
    const macKey = cek.slice(0, cek.length / 2);
    const encKey = cek.slice(cek.length / 2);
    const algorithm = encKey.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc';
    const cipher = crypto.createCipheriv(algorithm, encKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

    const al = Buffer.alloc(8);
    // AAD length in bits
    const aadBits = aad.length * 8;
    al.writeUInt32BE( Math.floor(aadBits / 0x100000000), 0); // high bits (usually 0)
    al.writeUInt32BE(aadBits & 0xffffffff, 4);

    const hmacAlg = alg === 'A128CBC-HS256' ? 'sha256' : 'sha512';
    const h = crypto.createHmac(hmacAlg, macKey);
    h.update(aad);
    h.update(iv);
    h.update(ciphertext);
    h.update(al);
    const fullTag = h.digest();
    const tagLen = fullTag.length / 2; // tag is left-most half
    const tag = fullTag.slice(0, tagLen);
    return { ciphertext, tag };
}

function aesCbcHmacDecrypt(cek: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer, aad: Buffer, alg: string) {
    const macKey = cek.slice(0, cek.length / 2);
    const encKey = cek.slice(cek.length / 2);
    const algorithm = encKey.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc';

    const al = Buffer.alloc(8);
    const aadBits = aad.length * 8;
    al.writeUInt32BE( Math.floor(aadBits / 0x100000000), 0);
    al.writeUInt32BE(aadBits & 0xffffffff, 4);

    const hmacAlg = alg === 'A128CBC-HS256' ? 'sha256' : 'sha512';
    const h = crypto.createHmac(hmacAlg, macKey);
    h.update(aad);
    h.update(iv);
    h.update(ciphertext);
    h.update(al);
    const fullTag = h.digest();
    const expectedTag = fullTag.slice(0, fullTag.length / 2);
    if (!crypto.timingSafeEqual(expectedTag, tag)) throw new Error('Authentication tag mismatch');

    const decipher = crypto.createDecipheriv(algorithm, encKey, iv);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext;
}

// AES Key Wrap (RFC 3394) - wrap
function aesKeyWrap(kek: Buffer, plaintext: Buffer): Buffer {
    // n = plaintext.length / 8
    if (plaintext.length % 8 !== 0) throw new Error('Plaintext must be multiple of 64 bits');
    const n = plaintext.length / 8;
    const R: Buffer[] = [];
    for (let i = 0; i < n; i++) R[i] = plaintext.slice(i * 8, i * 8 + 8);
    let A = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
    const cipher = (key: Buffer, block: Buffer) => {
        const c = crypto.createCipheriv(`aes-${key.length * 8}-ecb`, key, Buffer.alloc(0));
        c.setAutoPadding(false);
        return Buffer.concat([c.update(block), c.final()]);
    };
    for (let j = 0; j < 6; j++) {
        for (let i = 0; i < n; i++) {
            const B = cipher(kek, Buffer.concat([A, R[i]]));
            const t = (n * j) + i + 1;
            const tBuf = Buffer.alloc(8);
            tBuf.writeUInt32BE(0, 0);
            tBuf.writeUInt32BE(t, 4);
            A = Buffer.from(B.slice(0, 8));
            // A = MSB(64, B) XOR t
            for (let k = 0; k < 8; k++) A[k] = A[k] ^ tBuf[k];
            R[i] = B.slice(8);
        }
    }
    return Buffer.concat([A, ...R]);
}

// AES Key Unwrap (RFC 3394) - unwrap
function aesKeyUnwrap(kek: Buffer, ciphertext: Buffer): Buffer {
    if (ciphertext.length < 16 || ciphertext.length % 8 !== 0) throw new Error('Invalid ciphertext for AES Key Unwrap');
    const n = (ciphertext.length / 8) - 1;
    const R: Buffer[] = [];
    let A = ciphertext.slice(0, 8);
    for (let i = 0; i < n; i++) R[i] = ciphertext.slice(8 + i * 8, 8 + (i + 1) * 8);
    const decipher = (key: Buffer, block: Buffer) => {
        const d = crypto.createDecipheriv(`aes-${key.length * 8}-ecb`, key, Buffer.alloc(0));
        d.setAutoPadding(false);
        return Buffer.concat([d.update(block), d.final()]);
    };
    for (let j = 5; j >= 0; j--) {
        for (let i = n - 1; i >= 0; i--) {
            const t = (n * j) + i + 1;
            const tBuf = Buffer.alloc(8);
            tBuf.writeUInt32BE(0, 0);
            tBuf.writeUInt32BE(t, 4);
            const A_xor_t = Buffer.from(A);
            for (let k = 0; k < 8; k++) A_xor_t[k] = A_xor_t[k] ^ tBuf[k];
            const B = decipher(kek, Buffer.concat([A_xor_t, R[i]]));
            A = B.slice(0, 8);
            R[i] = B.slice(8);
        }
    }
    // verify A == IV
    const iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
    if (!A.equals(iv)) throw new Error('Integrity check failed for AES Key Unwrap');
    return Buffer.concat(R);
}

function intToBuffer(n: number) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(n, 0);
    return buf;
}

// Concat KDF per RFC7518 using SHA-256
function concatKDF(z: Buffer, keydatalen: number, alg: string, apu?: Buffer, apv?: Buffer): Buffer {
    const hashLen = 32; // SHA-256
    const reps = Math.ceil(keydatalen / (hashLen * 8));
    const algBuf = Buffer.from(alg, 'utf8');
    const otherInfo = Buffer.concat([
        intToBuffer(algBuf.length), algBuf,
        intToBuffer(apu ? apu.length : 0), apu || Buffer.alloc(0),
        intToBuffer(apv ? apv.length : 0), apv || Buffer.alloc(0),
        intToBuffer(keydatalen), // SuppPubInfo: keydatalen in bits
    ]);
    const out = Buffer.alloc(reps * hashLen);
    for (let counter = 1; counter <= reps; counter++) {
        const ctr = intToBuffer(counter);
        const hash = crypto.createHash('sha256');
        hash.update(ctr);
        hash.update(z);
        hash.update(otherInfo);
        const digest = hash.digest();
        digest.copy(out, (counter - 1) * hashLen);
    }
    return out.slice(0, keydatalen / 8);
}

function jwkToUncompressedPublicKey(jwk: JWK): Buffer {
    // supports EC keys with x,y base64url
    const x = base64urlDecode(jwk.x);
    const y = base64urlDecode(jwk.y);
    return Buffer.concat([Buffer.from([0x04]), x, y]);
}

function curveNameFromCrv(crv: string): string {
    switch (crv) {
        case 'P-256': return 'prime256v1';
        case 'P-384': return 'secp384r1';
        case 'P-521': return 'secp521r1';
        case 'secp256k1': return 'secp256k1';
        default: throw new Error('Unsupported curve: ' + crv);
    }
}

export async function encryptCompact(plaintext: Buffer | string, recipient: { alg: string; key: any }, headerInput: any = {}, enc: 'A128GCM' | 'A256GCM' | 'A128CBC-HS256' | 'A256CBC-HS512' = 'A256GCM') {
    return jweService.encryptCompact(plaintext, recipient, headerInput, enc);
}

export async function decryptCompact(token: string, keyOrLookup: any | ((header: any) => any | Promise<any>)) {
    return jweService.decryptCompact(token, keyOrLookup);
}

// General JSON Serialization (multi-recipient)
export async function encryptGeneral(plaintext: Buffer | string, recipients: Array<{ alg: string; key: any; header?: any; }>, protectedHeader: any = {}, unprotectedHeader: any = {}, enc: 'A128GCM' | 'A256GCM' | 'A128CBC-HS256' | 'A256CBC-HS512' = 'A256GCM') {
    return jweService.encryptGeneral(plaintext, recipients, protectedHeader, unprotectedHeader, enc);
}

export async function decryptGeneral(jwe: any, keyOrLookup: any | ((header: any) => any | Promise<any>)) {
    const protectedRaw = jwe.protected || '';
    const protectedHeader = protectedRaw ? JSON.parse(base64urlDecode(protectedRaw).toString('utf8')) : {};
    try {
        validateJoseHeaders(protectedHeader, { context: 'jwe', expectedTyp: protectedHeader.typ || null });
    } catch (e) {
        if (e instanceof JoseHeaderError) throw new JWTClaimValidationError(e.message);
        throw e;
    }
    const enc = protectedHeader.enc as string;
    const cekLen = enc === 'A128GCM' ? 16 : 32;
    const iv = base64urlDecode(jwe.iv);
    const ciphertext = base64urlDecode(jwe.ciphertext);
    const tag = base64urlDecode(jwe.tag);

    // iterate recipients to find one we can decrypt
    for (const rec of jwe.recipients) {
        const hdr = Object.assign({}, protectedHeader, jwe.unprotected || {}, rec.header || {});
        try {
            validateJoseHeaders(hdr, { context: 'jwe', expectedTyp: hdr.typ || null });
        } catch (e) {
            // if header invalid for this recipient, skip
            continue;
        }
        let key: any;
        if (typeof keyOrLookup === 'function') key = await Promise.resolve(keyOrLookup(hdr));
        else if (keyOrLookup && (Array.isArray(keyOrLookup) || (typeof keyOrLookup === 'object' && Array.isArray((keyOrLookup as any).keys)))) key = resolveJwkFromHeader(keyOrLookup as any, hdr);
        else key = keyOrLookup;
        const resolved = resolveKey(key);
        let cek: Buffer | undefined;
        const alg = hdr.alg as string;
        try {
            if (alg === 'dir') {
                if (!resolved || !Buffer.isBuffer(resolved)) throw new Error('dir requires CEK bytes');
                cek = resolved as Buffer;
            } else if (alg === 'RSA-OAEP' || alg === 'RSA-OAEP-256') {
                if (!resolved) throw new Error('Missing RSA private key');
                const oaepHash = alg === 'RSA-OAEP-256' ? 'sha256' : 'sha1';
                cek = crypto.privateDecrypt({ key: resolved as KeyLike, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash }, rec.encrypted_key ? base64urlDecode(rec.encrypted_key) : Buffer.alloc(0));
            } else if (alg === 'RSA1_5') {
                if (!resolved) throw new Error('Missing RSA private key');
                cek = crypto.privateDecrypt({ key: resolved as KeyLike, padding: crypto.constants.RSA_PKCS1_PADDING }, rec.encrypted_key ? base64urlDecode(rec.encrypted_key) : Buffer.alloc(0));
            } else if (alg === 'A128KW' || alg === 'A256KW') {
                if (!resolved || !Buffer.isBuffer(resolved)) throw new Error('Missing symmetric KEK');
                cek = aesKeyUnwrap(resolved as Buffer, base64urlDecode(rec.encrypted_key));
            } else if (alg.startsWith('ECDH-ES')) {
                if (!hdr.epk) continue; // cannot handle
                // handle ECDH-ES+A*KW
                if (alg.includes('+')) {
                    const epk = hdr.epk as JWK;
                    const recPrivJwk = key && key.kty ? key as JWK : undefined;
                    if (!recPrivJwk) continue;
                    const curve = curveNameFromCrv(epk.crv);
                    const ecdh = crypto.createECDH(curve);
                    if (!recPrivJwk.d) continue;
                    const d = base64urlDecode(recPrivJwk.d);
                    ecdh.setPrivateKey(d);
                    const epkPub = jwkToUncompressedPublicKey(epk);
                    const z = ecdh.computeSecret(epkPub);
                    const algKW = alg.split('+')[1];
                    const kekLen = algKW === 'A128KW' ? 16 : 32;
                    const kek = concatKDF(z, kekLen * 8, algKW);
                    cek = aesKeyUnwrap(kek, base64urlDecode(rec.encrypted_key));
                } else {
                    // ECDH-ES direct CEK derivation not supported in general mode here
                    continue;
                }
            }
        } catch (e) {
            // try next recipient
            continue;
        }

        if (!cek) continue;
        const aadBuf = Buffer.from(protectedRaw, 'ascii');
        let pt: Buffer;
        if (enc === 'A128GCM' || enc === 'A256GCM') {
            pt = aesGcmDecrypt(cek, iv, ciphertext, tag, aadBuf);
        } else if (enc === 'A128CBC-HS256' || enc === 'A256CBC-HS512') {
            pt = aesCbcHmacDecrypt(cek, iv, ciphertext, tag, aadBuf, enc);
        } else continue;
        try { return JSON.parse(pt.toString('utf8')); } catch { return pt; }
    }

    throw new Error('Unable to decrypt JWE for any recipient');
}

/**
 * JWEService: class-based API for JWE operations
 */
export class JWEService {
    async encryptCompact(plaintext: Buffer | string, recipient: { alg: string; key: any }, headerInput: any = {}, enc: 'A128GCM' | 'A256GCM' | 'A128CBC-HS256' | 'A256CBC-HS512' = 'A256GCM') {
        const pt = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext;
        const header: any = Object.assign({ alg: recipient.alg, enc }, headerInput || {});
        try {
            validateJoseHeaders(header, { context: 'jwe', expectedTyp: null });
        } catch (e) {
            if (e instanceof JoseHeaderError) throw new JWTClaimValidationError(e.message);
            throw e;
        }

        let cekLen: number;
        if (enc === 'A128GCM') cekLen = 16;
        else if (enc === 'A256GCM') cekLen = 32;
        else if (enc === 'A128CBC-HS256') cekLen = 32;
        else if (enc === 'A256CBC-HS512') cekLen = 64;
        else throw new Error('Unsupported enc');
        let cek = rand(cekLen);
        let encryptedKey = Buffer.alloc(0);

        if (recipient.alg === 'dir') {
            const resolved = resolveKey(recipient.key);
            if (!resolved) throw new Error('Missing key for alg "dir"');
            if (Buffer.isBuffer(resolved)) cek = resolved as any; else throw new Error('dir key must be raw bytes');
        } else if (recipient.alg === 'RSA-OAEP' || recipient.alg === 'RSA-OAEP-256') {
            const pub = resolveKey(recipient.key);
            if (!pub) throw new Error('Missing RSA public key');
            const oaepHash = recipient.alg === 'RSA-OAEP-256' ? 'sha256' : 'sha1';
            encryptedKey = crypto.publicEncrypt({ key: pub as KeyLike, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash }, cek);
        } else if (recipient.alg === 'ECDH-ES') {
            const recJwk = typeof recipient.key === 'object' && (recipient.key.kty === 'EC' || recipient.key.crv) ? recipient.key as JWK : undefined;
            if (!recJwk) throw new Error('ECDH-ES requires recipient EC public JWK');
            const curve = curveNameFromCrv(recJwk.crv);
            const ecdh = crypto.createECDH(curve);
            ecdh.generateKeys();
            const epkPublic = ecdh.getPublicKey();
            const keyLen = (epkPublic.length - 1) / 2;
            const x = epkPublic.slice(1, 1 + keyLen);
            const y = epkPublic.slice(1 + keyLen);
            header.epk = { kty: 'EC', crv: recJwk.crv, x: base64urlEncode(x), y: base64urlEncode(y) };
            const recPub = jwkToUncompressedPublicKey(recJwk);
            const z = ecdh.computeSecret(recPub);
            cek = concatKDF(z, cekLen * 8, enc) as any;
        } else {
            if (recipient.alg === 'RSA1_5') {
                const pub = resolveKey(recipient.key);
                if (!pub) throw new Error('Missing RSA public key');
                encryptedKey = crypto.publicEncrypt({ key: pub as KeyLike, padding: crypto.constants.RSA_PKCS1_PADDING }, cek);
            } else if (recipient.alg === 'A128KW' || recipient.alg === 'A256KW') {
                const kek = resolveKey(recipient.key);
                if (!kek || !Buffer.isBuffer(kek)) throw new Error('Missing symmetric KEK for A128KW/A256KW');
                encryptedKey = aesKeyWrap(kek as any, cek as any) as any;
            } else if (recipient.alg === 'ECDH-ES+A128KW' || recipient.alg === 'ECDH-ES+A256KW') {
                const recJwk = typeof recipient.key === 'object' && (recipient.key.kty === 'EC' || recipient.key.crv) ? recipient.key as JWK : undefined;
                if (!recJwk) throw new Error('ECDH-ES requires recipient EC public JWK');
                const curve = curveNameFromCrv(recJwk.crv);
                const ecdh = crypto.createECDH(curve);
                ecdh.generateKeys();
                const epkPublic = ecdh.getPublicKey();
                const keyLen = (epkPublic.length - 1) / 2;
                const x = epkPublic.slice(1, 1 + keyLen);
                const y = epkPublic.slice(1 + keyLen);
                header.epk = { kty: 'EC', crv: recJwk.crv, x: base64urlEncode(x), y: base64urlEncode(y) };
                const recPub = jwkToUncompressedPublicKey(recJwk);
                const z = ecdh.computeSecret(recPub);
                const kekLen = recipient.alg === 'ECDH-ES+A128KW' ? 16 : 32;
                const algKW = recipient.alg.split('+')[1];
                const kek = concatKDF(z, kekLen * 8, algKW) as any;
                encryptedKey = aesKeyWrap(kek as any, cek as any) as any;
            } else {
                throw new Error('Unsupported alg: ' + recipient.alg);
            }
        }

        const iv = enc.startsWith('A') && enc.includes('GCM') ? rand(12) : rand(16);
        const encodedHeader = base64urlEncode(JSON.stringify(header));
        const aad = Buffer.from(encodedHeader, 'ascii');
        let ciphertext: Buffer, tag: Buffer;
        if (enc === 'A128GCM' || enc === 'A256GCM') {
            const r = aesGcmEncrypt(cek, iv, pt, aad);
            ciphertext = r.ciphertext; tag = r.tag;
        } else if (enc === 'A128CBC-HS256' || enc === 'A256CBC-HS512') {
            const r = aesCbcHmacEncrypt(cek, iv, pt, aad, enc);
            ciphertext = r.ciphertext; tag = r.tag;
        } else {
            throw new Error('Unsupported enc');
        }

        const parts = [encodedHeader, encryptedKey.length ? base64urlEncode(encryptedKey) : '', base64urlEncode(iv), base64urlEncode(ciphertext), base64urlEncode(tag)];
        return parts.join('.');
    }

    async decryptCompact(token: string, keyOrLookup: any | ((header: any) => any | Promise<any>)) {
        const parts = token.split('.');
        if (parts.length !== 5) throw new JWTClaimValidationError('JWE Compact must have five parts');
        const header = JSON.parse(base64urlDecode(parts[0]).toString('utf8')) as any;
        try {
            validateJoseHeaders(header, { context: 'jwe', expectedTyp: null });
        } catch (e) {
            if (e instanceof JoseHeaderError) throw new JWTClaimValidationError(e.message);
            throw e;
        }
        if (!header.alg) throw new JWTClaimValidationError('Missing alg in JWE header');
        const enc = header.enc as string;
        const alg = header.alg as string;
        const encryptedKey = parts[1] ? base64urlDecode(parts[1]) : Buffer.alloc(0);
        const iv = base64urlDecode(parts[2]);
        const ciphertext = base64urlDecode(parts[3]);
        const tag = base64urlDecode(parts[4]);

        let key: any;
        if (typeof keyOrLookup === 'function') key = await Promise.resolve(keyOrLookup(header));
        else if (keyOrLookup && (Array.isArray(keyOrLookup) || (typeof keyOrLookup === 'object' && Array.isArray((keyOrLookup as any).keys)))) key = resolveJwkFromHeader(keyOrLookup as any, header);
        else key = keyOrLookup;
        const resolved = resolveKey(key);

        let cekLen: number;
        if (enc === 'A128GCM') cekLen = 16;
        else if (enc === 'A256GCM') cekLen = 32;
        else if (enc === 'A128CBC-HS256') cekLen = 32;
        else if (enc === 'A256CBC-HS512') cekLen = 64;
        else throw new JWTClaimValidationError('Unsupported enc');
        let cek: Buffer;

        if (alg === 'dir') {
            if (!resolved || !Buffer.isBuffer(resolved)) throw new Error('dir requires raw CEK');
            cek = resolved as Buffer;
        } else if (alg === 'RSA-OAEP' || alg === 'RSA-OAEP-256') {
            if (!resolved) throw new Error('Missing RSA private key');
            const oaepHash = alg === 'RSA-OAEP-256' ? 'sha256' : 'sha1';
            cek = crypto.privateDecrypt({ key: resolved as KeyLike, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash }, encryptedKey);
        } else if (alg === 'ECDH-ES') {
            if (!header.epk) throw new Error('Missing epk in header for ECDH-ES');
            const epk = header.epk as JWK;
            const recPrivJwk = key && key.kty ? key as JWK : undefined;
            if (!recPrivJwk) throw new Error('ECDH-ES requires recipient private JWK');
            const curve = curveNameFromCrv(epk.crv);
            const ecdh = crypto.createECDH(curve);
            if (!recPrivJwk.d) throw new Error('Recipient JWK missing private parameter d');
            const d = base64urlDecode(recPrivJwk.d);
            ecdh.setPrivateKey(d);
            const epkPub = jwkToUncompressedPublicKey(epk);
            const z = ecdh.computeSecret(epkPub);
            cek = concatKDF(z, cekLen * 8, enc);
        } else {
            if (alg === 'RSA1_5') {
                if (!resolved) throw new Error('Missing RSA private key');
                cek = crypto.privateDecrypt({ key: resolved as KeyLike, padding: crypto.constants.RSA_PKCS1_PADDING }, encryptedKey);
            } else if (alg === 'A128KW' || alg === 'A256KW') {
                if (!resolved || !Buffer.isBuffer(resolved)) throw new Error('Missing symmetric KEK for unwrap');
                cek = aesKeyUnwrap(resolved as Buffer, encryptedKey);
            } else if (alg === 'ECDH-ES+A128KW' || alg === 'ECDH-ES+A256KW') {
                if (!header.epk) throw new Error('Missing epk in header for ECDH-ES');
                const epk = header.epk as JWK;
                const recPrivJwk = key && key.kty ? key as JWK : undefined;
                if (!recPrivJwk) throw new Error('ECDH-ES requires recipient private JWK');
                const curve = curveNameFromCrv(epk.crv);
                const ecdh = crypto.createECDH(curve);
                if (!recPrivJwk.d) throw new Error('Recipient JWK missing private parameter d');
                const d = base64urlDecode(recPrivJwk.d);
                ecdh.setPrivateKey(d);
                const epkPub = jwkToUncompressedPublicKey(epk);
                const z = ecdh.computeSecret(epkPub);
                const kekLen = alg === 'ECDH-ES+A128KW' ? 16 : 32;
                const algKW = alg.split('+')[1];
                const kek = concatKDF(z, kekLen * 8, algKW);
                cek = aesKeyUnwrap(kek, encryptedKey);
            } else {
                throw new Error('Unsupported alg: ' + alg);
            }
        }

        const aad = Buffer.from(parts[0], 'ascii');
        let plaintext: Buffer;
        if (enc === 'A128GCM' || enc === 'A256GCM') plaintext = aesGcmDecrypt(cek, iv, ciphertext, tag, aad);
        else plaintext = aesCbcHmacDecrypt(cek, iv, ciphertext, tag, aad, enc);
        if (header.cty === 'JWT') return plaintext.toString('utf8');
        try { return JSON.parse(plaintext.toString('utf8')); } catch { return plaintext; }
    }

    async encryptGeneral(plaintext: Buffer | string, recipients: Array<{ alg: string; key: any; header?: any; }>, protectedHeader: any = {}, unprotectedHeader: any = {}, enc: 'A128GCM' | 'A256GCM' | 'A128CBC-HS256' | 'A256CBC-HS512' = 'A256GCM') {
        const pt = typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext;
        const headerBase: any = Object.assign({}, protectedHeader);
        headerBase.enc = enc;
        let cekLen: number;
        if (enc === 'A128GCM') cekLen = 16;
        else if (enc === 'A256GCM') cekLen = 32;
        else if (enc === 'A128CBC-HS256') cekLen = 32;
        else if (enc === 'A256CBC-HS512') cekLen = 64;
        else throw new Error('Unsupported enc');
        const cek = rand(cekLen);

        const iv = (enc === 'A128GCM' || enc === 'A256GCM') ? rand(12) : rand(16);
        const aad = '';
        const encodedProtected = base64urlEncode(JSON.stringify(headerBase));
        const aadBuf = Buffer.from(encodedProtected, 'ascii');

        let ciphertext: Buffer, tag: Buffer;
        if (enc === 'A128GCM' || enc === 'A256GCM') {
            const r = aesGcmEncrypt(cek, iv, pt, aadBuf);
            ciphertext = r.ciphertext; tag = r.tag;
        } else {
            const r = aesCbcHmacEncrypt(cek, iv, pt, aadBuf, enc);
            ciphertext = r.ciphertext; tag = r.tag;
        }

        const recipientsOut: any[] = [];

        for (const r of recipients) {
            const hdr = Object.assign({}, r.header || {});
            try {
                validateJoseHeaders(hdr, { context: 'jwe', expectedTyp: hdr.typ || null });
            } catch (e) {
                if (e instanceof JoseHeaderError) throw new JWTClaimValidationError(e.message);
                throw e;
            }
            let encryptedKey = Buffer.alloc(0);

            if (r.alg === 'dir') {
                encryptedKey = Buffer.alloc(0);
            } else if (r.alg === 'RSA-OAEP' || r.alg === 'RSA-OAEP-256') {
                const pub = resolveKey(r.key);
                if (!pub) throw new Error('Missing RSA public key');
                const oaepHash = r.alg === 'RSA-OAEP-256' ? 'sha256' : 'sha1';
                encryptedKey = crypto.publicEncrypt({ key: pub as KeyLike, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash }, cek);
            } else if (r.alg === 'RSA1_5') {
                const pub = resolveKey(r.key);
                if (!pub) throw new Error('Missing RSA public key');
                encryptedKey = crypto.publicEncrypt({ key: pub as KeyLike, padding: crypto.constants.RSA_PKCS1_PADDING }, cek);
            } else if (r.alg === 'A128KW' || r.alg === 'A256KW') {
                const kek = resolveKey(r.key);
                if (!kek || !Buffer.isBuffer(kek)) throw new Error('Missing symmetric KEK for A*KW');
                encryptedKey = aesKeyWrap(kek as any, cek as any) as any;
            } else if (r.alg === 'ECDH-ES' || r.alg.startsWith('ECDH-ES+')) {
                const recJwk = typeof r.key === 'object' && (r.key.kty === 'EC' || r.key.crv) ? r.key as JWK : undefined;
                if (!recJwk) throw new Error('ECDH requires recipient EC public JWK');
                const curve = curveNameFromCrv(recJwk.crv);
                const ecdh = crypto.createECDH(curve);
                ecdh.generateKeys();
                const epkPublic = ecdh.getPublicKey();
                const keyLen = (epkPublic.length - 1) / 2;
                const x = epkPublic.slice(1, 1 + keyLen);
                const y = epkPublic.slice(1 + keyLen);
                hdr.epk = { kty: 'EC', crv: recJwk.crv, x: base64urlEncode(x), y: base64urlEncode(y) };
                const recPub = jwkToUncompressedPublicKey(recJwk);
                const z = ecdh.computeSecret(recPub);
                if (r.alg === 'ECDH-ES') {
                    throw new Error('ECDH-ES (direct CEK derivation) not supported in multi-recipient general mode; use ECDH-ES+A*KW');
                } else {
                    const algKW = r.alg.split('+')[1];
                    const kekLen = algKW === 'A128KW' ? 16 : 32;
                    const kek = concatKDF(z, kekLen * 8, algKW) as any;
                    encryptedKey = aesKeyWrap(kek as any, cek as any) as any;
                }
            } else {
                throw new Error('Unsupported alg in general encryption: ' + r.alg);
            }

            // include alg in per-recipient header so decryptors can select proper flow
            hdr.alg = r.alg;
            recipientsOut.push({ header: hdr, encrypted_key: encryptedKey.length ? base64urlEncode(encryptedKey) : '' });
        }

        const out: any = { protected: encodedProtected };
        if (Object.keys(unprotectedHeader || {}).length) out.unprotected = unprotectedHeader;
        out.recipients = recipientsOut;
        out.iv = base64urlEncode(iv);
        out.ciphertext = base64urlEncode(ciphertext);
        out.tag = base64urlEncode(tag);
        return out;
    }

    async decryptGeneral(jwe: any, keyOrLookup: any | ((header: any) => any | Promise<any>)) {
        const protectedRaw = jwe.protected || '';
        const protectedHeader = protectedRaw ? JSON.parse(base64urlDecode(protectedRaw).toString('utf8')) : {};
        try {
            validateJoseHeaders(protectedHeader, { context: 'jwe', expectedTyp: protectedHeader.typ || null });
        } catch (e) {
            if (e instanceof JoseHeaderError) throw new JWTClaimValidationError(e.message);
            throw e;
        }
        const enc = protectedHeader.enc as string;
        let cekLen: number;
        if (enc === 'A128GCM') cekLen = 16;
        else if (enc === 'A256GCM') cekLen = 32;
        else if (enc === 'A128CBC-HS256') cekLen = 32;
        else if (enc === 'A256CBC-HS512') cekLen = 64;
        else throw new JWTClaimValidationError('Unsupported enc');
        const iv = base64urlDecode(jwe.iv);
        const ciphertext = base64urlDecode(jwe.ciphertext);
        const tag = base64urlDecode(jwe.tag);

        for (const rec of jwe.recipients) {
            const hdr = Object.assign({}, protectedHeader, jwe.unprotected || {}, rec.header || {});
            try {
                validateJoseHeaders(hdr, { context: 'jwe', expectedTyp: hdr.typ || null });
            } catch (e) {
                continue;
            }
            let key: any;
            if (typeof keyOrLookup === 'function') key = await Promise.resolve(keyOrLookup(hdr));
            else if (keyOrLookup && (Array.isArray(keyOrLookup) || (typeof keyOrLookup === 'object' && Array.isArray((keyOrLookup as any).keys)))) key = resolveJwkFromHeader(keyOrLookup as any, hdr);
            else key = keyOrLookup;
            const resolved = resolveKey(key);
            let cek: Buffer | undefined;
            const alg = hdr.alg as string;
            try {
                if (alg === 'dir') {
                    if (!resolved || !Buffer.isBuffer(resolved)) throw new Error('dir requires CEK bytes');
                    cek = resolved as Buffer;
                } else if (alg === 'RSA-OAEP' || alg === 'RSA-OAEP-256') {
                    if (!resolved) throw new Error('Missing RSA private key');
                    const oaepHash = alg === 'RSA-OAEP-256' ? 'sha256' : 'sha1';
                    cek = crypto.privateDecrypt({ key: resolved as KeyLike, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash }, rec.encrypted_key ? base64urlDecode(rec.encrypted_key) : Buffer.alloc(0));
                } else if (alg === 'RSA1_5') {
                    if (!resolved) throw new Error('Missing RSA private key');
                    cek = crypto.privateDecrypt({ key: resolved as KeyLike, padding: crypto.constants.RSA_PKCS1_PADDING }, rec.encrypted_key ? base64urlDecode(rec.encrypted_key) : Buffer.alloc(0));
                } else if (alg === 'A128KW' || alg === 'A256KW') {
                    if (!resolved || !Buffer.isBuffer(resolved)) throw new Error('Missing symmetric KEK');
                    cek = aesKeyUnwrap(resolved as Buffer, base64urlDecode(rec.encrypted_key));
                } else if (alg.startsWith('ECDH-ES')) {
                    if (!hdr.epk) continue;
                    if (alg.includes('+')) {
                        const epk = hdr.epk as JWK;
                        const recPrivJwk = key && key.kty ? key as JWK : undefined;
                        if (!recPrivJwk) continue;
                        const curve = curveNameFromCrv(epk.crv);
                        const ecdh = crypto.createECDH(curve);
                        if (!recPrivJwk.d) continue;
                        const d = base64urlDecode(recPrivJwk.d);
                        ecdh.setPrivateKey(d);
                        const epkPub = jwkToUncompressedPublicKey(epk);
                        const z = ecdh.computeSecret(epkPub);
                        const algKW = alg.split('+')[1];
                        const kekLen = algKW === 'A128KW' ? 16 : 32;
                        const kek = concatKDF(z, kekLen * 8, algKW);
                        cek = aesKeyUnwrap(kek, base64urlDecode(rec.encrypted_key));
                    } else {
                        continue;
                    }
                }
            } catch (e) {
                continue;
            }

                if (!cek) continue;
            const aadBuf = Buffer.from(protectedRaw, 'ascii');
            let pt: Buffer;
            if (enc === 'A128GCM' || enc === 'A256GCM') pt = aesGcmDecrypt(cek, iv, ciphertext, tag, aadBuf);
            else pt = aesCbcHmacDecrypt(cek, iv, ciphertext, tag, aadBuf, enc);
            try { return JSON.parse(pt.toString('utf8')); } catch { return pt; }
        }

        throw new Error('Unable to decrypt JWE for any recipient');
    }
}

export const jweService = new JWEService();
