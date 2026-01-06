const assert: any = require('assert');
const { validateJoseHeaders } = require('../header');
const lib: any = require('../index');
const { signCompact, verifyCompact } = lib;

function shouldNotThrow(fn: () => void, msg?: string) {
  try {
    fn();
  } catch (e: any) {
    console.error('Unexpected throw:', e && (e.message || e.toString()));
    process.exitCode = 1;
    throw new Error(msg || 'Expected no throw');
  }
}

// Test 1: unknown custom header is ignored
shouldNotThrow(() => validateJoseHeaders({ alg: 'HS256', 'x-custom': 'v' }, { context: 'jws' }), 'Unknown custom header should be ignored');
console.log('OK: unknown custom header ignored');

// Test 2: crit with b64
shouldNotThrow(() => validateJoseHeaders({ alg: 'HS256', crit: ['b64'], b64: false }, { context: 'jws' }), 'crit b64 handling failed');
console.log('OK: crit b64 handled');

// Test 3: crit with unknown extension should throw
let threw = false;
try {
  validateJoseHeaders({ alg: 'HS256', crit: ['x-unknown'], 'x-unknown': 'v' }, { context: 'jws' });
} catch (e) {
  threw = true;
}
if (!threw) {
  console.error('Expected validateJoseHeaders to throw for unknown crit extension');
  process.exitCode = 1;
  throw new Error('crit unknown did not throw');
}
console.log('OK: unknown crit extension rejected');

// Test 4: sign/verify JWS with custom header
(async () => {
  const key = Buffer.from('secret');
  const header = { alg: 'HS256', 'x-foo': 'bar' };
  const token = await signCompact({ msg: 'hello' }, { key, protectedHeader: header });
  const verified = await verifyCompact(token, key);
  assert.deepStrictEqual(verified.payload, { msg: 'hello' });
  console.log('OK: JWS sign/verify with custom header');
})();

// finish
process.on('beforeExit', () => {
  if (!process.exitCode) console.log('All header tests passed');
});

export {};
