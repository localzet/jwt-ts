import * as assert from 'assert';
import { getJwkByKid, resolveJwkFromHeader } from '../jwks';

async function testGetByKid() {
    const keys = [
        { kid: 'a', alg: 'RS256', kty: 'RSA' },
        { kid: 'b', alg: 'HS256', kty: 'oct' }
    ];
    const found = getJwkByKid(keys, 'b');
    assert.strictEqual(found && found.kid, 'b');
    const byAlg = getJwkByKid(keys, undefined, 'RS256');
    assert.strictEqual(byAlg && byAlg.kid, 'a');
}

async function testResolveFromHeader() {
    const jwks = { keys: [ { kid: 'k1', alg: 'HS256', kty: 'oct' } ] };
    const header = { kid: 'k1', alg: 'HS256' };
    const r = resolveJwkFromHeader(jwks as any, header);
    assert.strictEqual(r && r.kid, 'k1');
}

async function run() {
    await testGetByKid();
    await testResolveFromHeader();
    console.log('JWKS tests passed');
}

run().catch(e => { console.error(e); process.exit(1); });
