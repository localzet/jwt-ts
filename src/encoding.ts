/*
 * Encoding helpers
 * - base64url encode/decode (RFC 7515 Appendix C)
 * - DER <-> JOSE ECDSA signature conversions (RFC 7518)
 */
export function base64urlEncode(input: Buffer | string): string {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
    return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export function base64urlDecode(input: string): Buffer {
    let str = input.replace(/-/g, '+').replace(/_/g, '/');
    const pad = str.length % 4;
    if (pad === 2) str += '==';
    else if (pad === 3) str += '=';
    else if (pad !== 0) throw new Error('Invalid base64url string');
    return Buffer.from(str, 'base64');
}

// Convert ECDSA DER signature to JOSE (r||s) of fixed length
export function derToJose(signature: Buffer, keySize: number): Buffer {
    // Minimal DER parser to extract r and s values
    let offset = 0;
    if (signature[offset++] !== 0x30) throw new Error('Invalid DER signature (no sequence)');

    const seqLenInfo = readLength(signature, offset);
    const seqLen = seqLenInfo.len;
    offset += seqLenInfo.size;

    if (signature[offset++] !== 0x02) throw new Error('Invalid DER signature (no integer r)');
    const rLenInfo = readLength(signature, offset);
    const rLen = rLenInfo.len;
    offset += rLenInfo.size;
    const r = signature.slice(offset, offset + rLen);
    offset += rLen;

    if (signature[offset++] !== 0x02) throw new Error('Invalid DER signature (no integer s)');
    const sLenInfo = readLength(signature, offset);
    const sLen = sLenInfo.len;
    offset += sLenInfo.size;
    const s = signature.slice(offset, offset + sLen);

    const partLen = Math.ceil(keySize / 8);
    const rBuf = padTo(r, partLen);
    const sBuf = padTo(s, partLen);
    return Buffer.concat([rBuf, sBuf]);
}

function readLength(buf: Buffer, offset: number) {
    const first = buf[offset];
    if (first === undefined) throw new Error('Invalid DER length');
    if (first < 0x80) return { len: first, size: 1 };
    const numBytes = first & 0x7f;
    if (numBytes === 0 || numBytes > 4) throw new Error('Unsupported DER length');
    let len = 0;
    for (let i = 0; i < numBytes; i++) {
        len = (len << 8) + buf[offset + 1 + i];
    }
    return { len, size: 1 + numBytes };
}

export function joseToDer(signature: Buffer): Buffer {
    const half = Math.floor(signature.length / 2);
    let r = signature.slice(0, half);
    let s = signature.slice(half);
    r = stripLeadingZeros(r) as any;
    s = stripLeadingZeros(s) as any;
    const rSeq = Buffer.concat([Buffer.from([0x02, r.length]), r]);
    const sSeq = Buffer.concat([Buffer.from([0x02, s.length]), s]);
    const contentLen = rSeq.length + sSeq.length;
    const lenBuf = writeLength(contentLen);
    const seq = Buffer.concat([Buffer.from([0x30]), lenBuf, rSeq, sSeq]);
    return seq;
}

function padTo(buf: Buffer, len: number): Buffer {
    if (buf.length === len) return buf;
    if (buf.length > len) return buf.slice(-len);
    const pad = Buffer.alloc(len - buf.length, 0);
    return Buffer.concat([pad, buf]);
}

function stripLeadingZeros(buf: Buffer): Buffer {
    let i = 0;
    while (i < buf.length - 1 && buf[i] === 0) i++;
    const out = buf.slice(i);
    if (out[0] & 0x80) {
        // ensure positive integer in DER, if high bit is set, prefix 0x00
        return Buffer.concat([Buffer.from([0x00]), out]);
    }
    return out;
}

function writeLength(len: number): Buffer {
    if (len < 0x80) return Buffer.from([len]);
    // long form
    const bytes: number[] = [];
    let v = len;
    while (v > 0) { bytes.unshift(v & 0xff); v >>= 8; }
    if (bytes.length > 127) throw new Error('Length too long');
    return Buffer.from([0x80 | bytes.length, ...bytes]);
}
