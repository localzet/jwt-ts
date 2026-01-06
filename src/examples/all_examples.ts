import * as crypto from 'crypto';
import { sign, verify } from '../jwt';
import { signCompact, verifyCompact } from '../jws';
import { encryptCompact, decryptCompact } from '../jwe';
import { jwkManager } from '../jwk';

async function run() {
    console.log('--- HS256 (HMAC) example ---');
    const hmacKey = Buffer.from('my-secret-key');
    const hsToken = await sign({ sub: 'alice', role: 'admin' }, hmacKey, { alg: 'HS256', exp: 120 });
    console.log('HS256 token:', hsToken);
    console.log('Verified payload:', await verify(hsToken, hmacKey));

    console.log('\n--- Unsecured (alg:none) example ---');
    const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const payload = Buffer.from(JSON.stringify({ foo: 'bar' })).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const unsecured = `${header}.${payload}.`;
    console.log('Unsecured JWT:', unsecured);

    console.log('\n--- Detached JWS (b64=false) example ---');
    const detachedHeader = { alg: 'HS256', b64: false, crit: ['b64'] } as any;
    const rawPayload = 'The quick brown fox';
    const detached = await signCompact(rawPayload, { key: hmacKey, protectedHeader: detachedHeader });
    console.log('Detached JWS:', detached);
    const verifiedDetached = await verifyCompact(detached, hmacKey, { detachedPayload: rawPayload });
    console.log('Detached verified payload:', verifiedDetached.payload.toString ? verifiedDetached.payload.toString() : verifiedDetached.payload);

    console.log('\n--- RSA (RS256) sign/verify + JWE RSA1_5 encrypt/decrypt ---');
    const { publicKey: rsaPub, privateKey: rsaPriv } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaToken = await sign({ sub: 'bob' }, rsaPriv, { alg: 'RS256' });
    console.log('RS256 token:', rsaToken);
    console.log('RS256 verify:', await verify(rsaToken, rsaPub));

    const jweRsa = await encryptCompact(JSON.stringify({ secret: 'sauce' }), { alg: 'RSA1_5', key: rsaPub }, { alg: 'RSA1_5' }, 'A256GCM');
    console.log('JWE RSA1_5 (A256GCM):', jweRsa);
    console.log('JWE RSA1_5 decrypt:', await decryptCompact(jweRsa, rsaPriv));

    console.log('\n--- ECDSA (ES256) and ECDH-ES+A128KW example ---');
    const { publicKey: ecPubObj, privateKey: ecPrivObj } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const ecJwk = jwkManager.keyObjectToJwk(ecPubObj);
    const signedEs = await sign({ aud: 'example' }, ecPrivObj, { alg: 'ES256' });
    console.log('ES256 token:', signedEs);
    console.log('ES256 verify:', await verify(signedEs, ecPubObj));

    const jweEcdh = await encryptCompact(JSON.stringify({ nested: 'yes' }), { alg: 'ECDH-ES+A128KW', key: ecJwk }, { alg: 'ECDH-ES+A128KW' }, 'A128GCM');
    console.log('JWE ECDH-ES+A128KW (A128GCM):', jweEcdh);
    const ecPrivJwk = jwkManager.keyObjectToJwk(ecPrivObj as crypto.KeyObject);
    console.log('JWE ECDH decrypt:', await decryptCompact(jweEcdh, ecPrivJwk));

    console.log('\n--- JWE dir (direct) with A128GCM and A128CBC-HS256 ---');
    const cekA128 = crypto.randomBytes(16);
    const jweDirGcm = await encryptCompact(JSON.stringify({ a: 1 }), { alg: 'dir', key: cekA128 }, { alg: 'dir' }, 'A128GCM');
    console.log('JWE dir A128GCM:', jweDirGcm);
    console.log('decrypt:', await decryptCompact(jweDirGcm, cekA128));

    const cekComposite = crypto.randomBytes(32); // 32 bytes CEK => A128CBC-HS256
    const jweDirCbc = await encryptCompact(JSON.stringify({ b: 2 }), { alg: 'dir', key: cekComposite }, { alg: 'dir' }, 'A128CBC-HS256');
    console.log('JWE dir A128CBC-HS256:', jweDirCbc);
    console.log('decrypt:', await decryptCompact(jweDirCbc, cekComposite));

    console.log('\n--- Nested JWT (sign then encrypt with cty=JWT) ---');
    const inner = await sign({ nested: true }, rsaPriv, { alg: 'RS256' });
    const nested = await encryptCompact(inner, { alg: 'RSA1_5', key: rsaPub }, { alg: 'RSA1_5', cty: 'JWT' }, 'A256GCM');
    console.log('Nested JWE:', nested);
    const decNested = await decryptCompact(nested, rsaPriv);
    console.log('Decrypted nested (raw JWT):', decNested);

    console.log('\n--- JWK/JWKS examples ---');
    const jwkPub = jwkManager.keyObjectToJwk(rsaPub);
    const jwkPriv = jwkManager.keyObjectToJwk(rsaPriv as crypto.KeyObject);
    console.log('RSA public JWK:', jwkPub);
    console.log('RSA private JWK thumbprint:', jwkManager.jwkThumbprint(jwkPriv));

    console.log('\nAll examples finished.');
}

run().catch(e => { console.error('Example failed:', e); process.exit(1); });
