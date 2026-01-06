import * as assert from 'assert';
import { jweService } from '../jwe';
import * as crypto from 'crypto';

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
    // Create two recipient EC keypairs
    const r1 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    const r2 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
    // Export public/private JWKs via KeyObject.export
    const pubJwk1 = r1.publicKey.export({ format: 'jwk' }) as any;
    const pubJwk2 = r2.publicKey.export({ format: 'jwk' }) as any;
    const privJwk2 = r2.privateKey.export({ format: 'jwk' }) as any;

    const recipients = [
        { alg: 'ECDH-ES+A128KW', key: pubJwk1 },
        { alg: 'ECDH-ES+A128KW', key: pubJwk2 }
    ];

    const jwe = await jweService.encryptGeneral('multi', recipients, {}, {}, 'A128GCM');
    console.log('DEBUG JWE recipients:', JSON.stringify(jwe.recipients));
    // decrypt with second recipient's private JWK
    const pt = await jweService.decryptGeneral(jwe, (hdr:any) => {
        // return the matching private jwk when kid/epk present
        console.log('DEBUG hdr.alg/hdr.epk:', hdr.alg, !!hdr.epk);
        return privJwk2;
    });
    assert.strictEqual(pt.toString ? pt.toString() : pt, 'multi');
}

async function run() {
    await testDir();
    await testRsaOaep();
    await testAesKw();
    await testAes256Kw();
    await testEcdhEsA128kwMultiRecipient();
    console.log('JWE tests passed');
}

run().catch(e => { console.error(e); process.exit(1); });
