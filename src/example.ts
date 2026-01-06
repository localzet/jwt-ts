import { sign, verify } from './jwt';

async function run() {
    // HMAC example
    const token = await sign({ sub: '123', name: 'Alice' }, 'secret', { alg: 'HS256', exp: 60 });
    console.log('HS256 token:', token);
    const payload = await verify(token, 'secret', { algorithms: ['HS256'] });
    console.log('Verified payload:', payload);

    // RSA example (generate keys externally or use openssl) - here we skip RSA runtime example
}

run().catch(err => {
    console.error(err);
    process.exit(1);
});
