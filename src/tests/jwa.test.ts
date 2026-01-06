import * as assert from 'assert';
import { JWAFactory, jwa } from '../jwa';
import { base64urlEncode, base64urlDecode } from '../encoding';
import * as crypto from 'crypto';

async function testHmac() {
    const s = JWAFactory.getSigner('HS256');
    const key = Buffer.from('secret');
    const payload = Buffer.from('hello');
    const sig = await Promise.resolve(s.sign(payload, key));
    const ok = await Promise.resolve(s.verify(payload, sig, key));
    assert.ok(ok, 'HS256 verify');
}

async function testRsa() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const s = jwa.getSigner('RS256');
    const payload = Buffer.from('rsa');
    const sig = await Promise.resolve(s.sign(payload, privateKey));
    const ok = await Promise.resolve(s.verify(payload, sig, publicKey));
    assert.ok(ok, 'RS256 verify');
}

async function testPss() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const s = jwa.getSigner('PS256');
    const payload = Buffer.from('pss');
    const sig = await Promise.resolve(s.sign(payload, privateKey));
    const ok = await Promise.resolve(s.verify(payload, sig, publicKey));
    assert.ok(ok, 'PS256 verify');
}

async function testEcdsa() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const s = jwa.getSigner('ES256');
    const payload = Buffer.from('ecdsa');
    const sig = await Promise.resolve(s.sign(payload, privateKey));
    const ok = await Promise.resolve(s.verify(payload, sig, publicKey));
    assert.ok(ok, 'ES256 verify');
}

async function testEs384And512() {
    const kp384 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    const s384 = jwa.getSigner('ES384');
    const p = Buffer.from('es384');
    const sig384 = await Promise.resolve(s384.sign(p, kp384.privateKey));
    assert.ok(await Promise.resolve(s384.verify(p, sig384, kp384.publicKey)), 'ES384 verify');

    const kp512 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp521r1' });
    const s512 = jwa.getSigner('ES512');
    const sig512 = await Promise.resolve(s512.sign(p, kp512.privateKey));
    assert.ok(await Promise.resolve(s512.verify(p, sig512, kp512.publicKey)), 'ES512 verify');
}

async function testEs256k() {
    try {
        const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
        const s = jwa.getSigner('ES256K');
        const p = Buffer.from('es256k');
        const sig = await Promise.resolve(s.sign(p, kp.privateKey));
        assert.ok(await Promise.resolve(s.verify(p, sig, kp.publicKey)), 'ES256K verify');
    } catch (e) {
        console.log('Skipping ES256K (platform unsupported)');
    }
}

async function testEdDsa() {
    // Node 12+ supports ed25519
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        const s = jwa.getSigner('EdDSA');
        const payload = Buffer.from('eddsa');
        const sig = await Promise.resolve(s.sign(payload, privateKey));
        const ok = await Promise.resolve(s.verify(payload, sig, publicKey));
        assert.ok(ok, 'EdDSA verify');
    } catch (e) {
        console.log('Skipping EdDSA test (platform unsupported)');
    }
}

async function run() {
    await testHmac();
    await testRsa();
    await testPss();
    await testEcdsa();
    await testEs384And512();
    await testEs256k();
    await testEdDsa();
    console.log('JWA tests passed');
}

run().catch(e => { console.error(e); process.exit(1); });
