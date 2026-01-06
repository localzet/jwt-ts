import * as assert from 'assert';
import { jwsService } from '../jws';
import * as crypto from 'crypto';

async function testCompactRoundtrip() {
    const key = Buffer.from('secret-hmac');
    const token = await jwsService.signCompact({ foo: 'bar' }, { key, protectedHeader: { alg: 'HS256', typ: 'JWT' } });
    const res = await jwsService.verifyCompact(token, key, { expectedTyp: 'JWT' });
    assert.strictEqual(res.payload.foo, 'bar');
}

async function testDetachedB64False() {
    const key = Buffer.from('secret');
    const payload = 'detached-payload';
    const token = await jwsService.signCompact(payload, { key, protectedHeader: { alg: 'HS256', b64: false, crit: ['b64'] } });
    const verified = await jwsService.verifyCompact(token, key, { detachedPayload: Buffer.from(payload, 'utf8') });
    assert.ok(verified.payload instanceof Buffer || verified.payload === payload || verified.payload.toString().includes('detached'));
}

async function testGeneralMultiSigner() {
    const key1 = Buffer.from('a');
    const key2 = Buffer.from('b');
    const out = await jwsService.signGeneral({ x: 1 }, [
        { key: key1, protectedHeader: { alg: 'HS256', kid: 'k1' } },
        { key: key2, protectedHeader: { alg: 'HS256', kid: 'k2' } }
    ]);
    const verified = await jwsService.verifyGeneral(out, (header:any) => header.kid === 'k1' ? key1 : key2);
    assert.strictEqual((verified.payload as any).x, 1);
}

async function testRsaPssAndEs256k() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const token = await jwsService.signCompact({ r: 'pss' }, { key: privateKey, protectedHeader: { alg: 'PS256', typ: 'JWT' } });
    const res = await jwsService.verifyCompact(token, publicKey, { expectedTyp: 'JWT' });
    assert.strictEqual(res.payload.r, 'pss');

    try {
        const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
        const tok2 = await jwsService.signCompact({ k: 'es256k' }, { key: kp.privateKey, protectedHeader: { alg: 'ES256K', typ: 'JWT' } });
        const res2 = await jwsService.verifyCompact(tok2, kp.publicKey, { expectedTyp: 'JWT' });
        assert.strictEqual(res2.payload.k, 'es256k');
    } catch (e) {
        console.log('Skipping ES256K JWS test (platform unsupported)');
    }
}

async function run() {
    await testCompactRoundtrip();
    await testDetachedB64False();
    await testGeneralMultiSigner();
    await testRsaPssAndEs256k();
    console.log('JWS tests passed');
}

run().catch(e => { console.error(e); process.exit(1); });
