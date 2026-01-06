import * as assert from 'assert';
import { sign, verify } from '../jwt';

async function testRejectNonStringIss() {
    const token = await sign({ iss: 123 }, 'secret', { alg: 'HS256' });
    try {
        await verify(token, 'secret');
        throw new Error('Expected verification to fail');
    } catch (e: any) {
        assert.strictEqual(e.name, 'JWTClaimValidationError');
    }
}

async function testRejectNonStringSub() {
    const token = await sign({ sub: { id: 1 } }, 'secret', { alg: 'HS256' });
    try {
        await verify(token, 'secret');
        throw new Error('Expected verification to fail');
    } catch (e: any) {
        assert.strictEqual(e.name, 'JWTClaimValidationError');
    }
}

async function testRejectInvalidAud() {
    const token = await sign({ aud: { foo: 'bar' } }, 'secret', { alg: 'HS256' });
    try {
        await verify(token, 'secret');
        throw new Error('Expected verification to fail');
    } catch (e: any) {
        assert.strictEqual(e.name, 'JWTClaimValidationError');
    }
}

async function testNoneAlgNonEmptySignature() {
    const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const payload = Buffer.from(JSON.stringify({})).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const token = `${header}.${payload}.abc`;
    try {
        await verify(token, 'secret');
        throw new Error('Expected verification to fail');
    } catch (e: any) {
        assert.strictEqual(e.name, 'InvalidSignatureError');
    }
}

async function run() {
    await testRejectNonStringIss();
    await testRejectNonStringSub();
    await testRejectInvalidAud();
    await testNoneAlgNonEmptySignature();
    console.log('Claim and none-alg tests passed');
}

run().catch(e => { console.error(e); process.exit(1); });
