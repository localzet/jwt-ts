import * as assert from 'assert';
import { jwtService } from '../jwt';
import * as crypto from 'crypto';

async function testSignVerifyClaims() {
    const key = Buffer.from('sekret');
    const token = await jwtService.sign({ sub: '123' }, key, { alg: 'HS256', exp: 60 });
    const payload = await jwtService.verify(token, key, { issuer: undefined });
    assert.strictEqual(payload.sub, '123');
}

async function testJwtClaimsDetailed() {
    const key = Buffer.from('sekret2');
    const now = Math.floor(Date.now() / 1000);
    const token = await jwtService.sign({ iss: 'me', aud: ['a1','a2'], nbf: now - 10, iat: now - 5, jti: 'j1' }, key, { alg: 'HS256', exp: 60 });
    const payload = await jwtService.verify(token, key, { issuer: 'me', audience: 'a1' as any });
    assert.strictEqual(payload.iss, 'me');
    assert.strictEqual(payload.jti, 'j1');
}

async function run() {
    await testSignVerifyClaims();
    await testJwtClaimsDetailed();
    console.log('JWT tests passed');
}

run().catch(e => { console.error(e); process.exit(1); });
