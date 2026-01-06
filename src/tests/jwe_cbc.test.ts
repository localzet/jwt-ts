import * as assert from 'assert';
import { encryptCompact, decryptCompact } from '../jwe';

async function testA128() {
    const key = Buffer.from('0123456789abcdef0123456789abcdef'); // 32 bytes CEK for A128CBC-HS256
    const recipient = { alg: 'dir', key };
    const plaintext = JSON.stringify({ foo: 'bar' });
    const token = await encryptCompact(plaintext, recipient, {}, 'A128CBC-HS256');
    const out = await decryptCompact(token, key);
    assert.strictEqual((out as any).foo, 'bar');
}

async function testA256() {
    const key = Buffer.alloc(64, 0x01); // 64 bytes CEK for A256CBC-HS512
    const recipient = { alg: 'dir', key };
    const plaintext = JSON.stringify({ baz: 42 });
    const token = await encryptCompact(plaintext, recipient, {}, 'A256CBC-HS512');
    const out = await decryptCompact(token, key);
    assert.strictEqual((out as any).baz, 42);
}

async function run() {
    await testA128();
    await testA256();
    console.log('JWE AES-CBC-HMAC tests passed');
}

run().catch(e => { console.error(e); process.exit(1); });
