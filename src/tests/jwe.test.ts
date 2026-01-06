const assert: any = require('assert');
const { signCompact, verifyCompact } = require('../jws');
const { encryptCompact, decryptCompact } = require('../jwe');
const { sign } = require('../jwt');
const { jweService } = require('../jwe');
import * as crypto from 'crypto';

async function testDetachedJws() {
  const key = Buffer.from('secret');
  const prot = { alg: 'HS256', b64: false, crit: ['b64'] };
  const payload = Buffer.from('raw-payload');
  const token = await signCompact(payload, { key, protectedHeader: prot });
  const verified = await verifyCompact(token, key, { detachedPayload: payload });
  if (!Buffer.isBuffer(verified.payload) || verified.payload.toString('utf8') !== 'raw-payload') {
    console.error('Detached JWS payload mismatch');
    process.exitCode = 1;
    throw new Error('Detached JWS failed');
  }
  console.log('OK: detached JWS (b64=false)');
}

async function testJweCompactCtyJwt() {
  const signingKey = Buffer.from('secret');
  const inner = await sign({ sub: 'alice' }, signingKey, { alg: 'HS256' });
  const cek = Buffer.from('0123456789abcdef0123456789abcdef'); // 32 bytes for A256GCM
  const jwe = await encryptCompact(inner, { alg: 'dir', key: cek }, { cty: 'JWT' }, 'A256GCM');
  const decrypted = await decryptCompact(jwe, cek);
  if (typeof decrypted !== 'string') {
    console.error('Expected nested JWT string when cty=JWT');
    process.exitCode = 1;
    throw new Error('JWE cty handling failed');
  }
  console.log('OK: JWE compact with cty=JWT returns raw nested JWT');
}

// --- additional JWE tests from jwe_more.test.ts ---
async function testDir() {
    const cek = crypto.randomBytes(32);
    const token = await jweService.encryptCompact('hello', { alg: 'dir', key: cek }, {});
    const pt = await jweService.decryptCompact(token, cek);
    assert.strictEqual(pt.toString ? pt.toString() : pt, 'hello');
}

async function testRsaOaep() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const token = await jweService.encryptCompact('secret', { alg: 'RSA-OAEP', key: publicKey }, {});
    const pt = await jweService.decryptCompact(token, privateKey);
    assert.strictEqual(pt.toString ? pt.toString() : pt, 'secret');
}

async function testAesKw() {
    const kek = crypto.randomBytes(16);
    const token = await jweService.encryptCompact('payload', { alg: 'A128KW', key: kek }, {});
    const pt = await jweService.decryptCompact(token, kek);
    assert.strictEqual(pt.toString ? pt.toString() : pt, 'payload');
}

async function testAes256Kw() {
    const kek = crypto.randomBytes(32);
    const token = await jweService.encryptCompact('payload256', { alg: 'A256KW', key: kek }, {});
    const pt = await jweService.decryptCompact(token, kek);
    assert.strictEqual(pt.toString ? pt.toString() : pt, 'payload256');
}

async function testEcdhEsA128kwMultiRecipient() {
    const r1 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const r2 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const pubJwk1 = r1.publicKey.export({ format: 'jwk' });
    const pubJwk2 = r2.publicKey.export({ format: 'jwk' });
    const privJwk2 = r2.privateKey.export({ format: 'jwk' });

    const recipients = [
        { alg: 'ECDH-ES+A128KW', key: pubJwk1 },
        { alg: 'ECDH-ES+A128KW', key: pubJwk2 }
    ];

    const jwe = await jweService.encryptGeneral('multi', recipients, {}, {}, 'A128GCM');
    // decrypt with second recipient's private JWK
    const pt = await jweService.decryptGeneral(jwe, (hdr: any) => privJwk2);
    assert.strictEqual(pt.toString ? pt.toString() : pt, 'multi');
}

async function run() {
  await testDetachedJws();
  await testJweCompactCtyJwt();
  await testDir();
  await testRsaOaep();
  await testAesKw();
  await testAes256Kw();
  await testEcdhEsA128kwMultiRecipient();
  console.log('JWE tests passed');
}

run().catch((e) => { console.error(e); process.exitCode = 1; });
