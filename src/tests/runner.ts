// Unified test runner: import each test file so they run sequentially.
import './header.test';
import './jwa.test';
import './jws.test';
import './jwe.test';
import './jwk.test';
import './jwt.test';
import './claim_and_none.test';
import './jwe_cbc.test';

// If tests call process.exit on failure, requiring them is sufficient.
console.log('All tests imported.');
