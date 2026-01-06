import * as assert from 'assert';
import { jwkToKeyObject, jwkThumbprint, pemToJwk, jwkToPEM } from '../jwk';
import * as crypto from 'crypto';

async function testRsaConversion() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
    const pem = privateKey.export({ type: 'pkcs1', format: 'pem' }) as string;
    const jwk = pemToJwk(pem);
    const ko = jwkToKeyObject(jwk);
    assert.ok(ko);
    const thumb = jwkThumbprint(jwk);
    assert.ok(typeof thumb === 'string');
}

async function run() {
    await testRsaConversion();
    console.log('JWK tests passed');
}

run().catch(e => { console.error(e); process.exit(1); });
