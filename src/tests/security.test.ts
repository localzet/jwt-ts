import * as assert from 'node:assert/strict';
import { sign, verify } from '../jwt';
import { signCompact, verifyCompact, signGeneral, verifyGeneral } from '../jws';
import { base64urlDecode } from '../encoding';
import { InvalidSignatureError } from '../errors';

async function run() {
    const secret = Buffer.from('test-only-hmac-key-with-enough-entropy');
    const token = await sign({ sub: 'user' }, secret, { alg: 'HS256' });
    const verified = await verify(token, secret);
    assert.equal(verified.sub, 'user');

    const forgedUnsigned = [
        Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url'),
        Buffer.from(JSON.stringify({ sub: 'admin' })).toString('base64url'),
        '',
    ].join('.');
    await assert.rejects(verify(forgedUnsigned, secret), InvalidSignatureError);
    await assert.rejects(verifyCompact(forgedUnsigned, secret), InvalidSignatureError);
    await assert.rejects(verifyCompact(forgedUnsigned, secret, { expectedAlg: 'none' }), InvalidSignatureError);

    const unsignedGeneral = await signGeneral({ sub: 'admin' }, [
        { key: null, protectedHeader: { alg: 'none' } },
    ]);
    await assert.rejects(verifyGeneral(unsignedGeneral, secret), InvalidSignatureError);

    const parts = token.split('.');
    parts[2] = 'AA'; // A valid base64url encoding but the wrong HMAC length.
    await assert.rejects(verify(parts.join('.'), secret), InvalidSignatureError);

    const compact = await signCompact({ sub: 'user' }, {
        key: secret,
        protectedHeader: { alg: 'HS256' },
    });
    const parts2 = compact.split('.');
    parts2[2] = 'AA';
    await assert.rejects(verifyCompact(parts2.join('.'), secret), InvalidSignatureError);

    for (const text of ['abc!', 'Zg==', 'Zg+', 'Z', 'Zh']) {
        assert.throws(() => base64urlDecode(text), /base64url/i);
    }
    assert.equal(base64urlDecode('Zg').toString('utf8'), 'f');

    console.log('JWT/JWS authentication boundary tests passed');
}

run().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
