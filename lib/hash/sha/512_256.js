'use strict';

var utils = require('../utils');

var SHA512 = require('./512');

// SHA-512/256, from FIPS 180-4 §5.3.6.2: the SHA-512 compression function with
// a distinct initial hash value, truncated to 256 bits. Distinct from SHA-256 —
// the digests differ — and distinct from a naive truncation of SHA-512, which
// is why the IV below is not SHA-512's.
//
// Added because node:crypto supports `sha512-256` and consumers that fall back
// to a pure-JavaScript implementation in the browser would otherwise have to
// throw for it, leaving the two paths disagreeing.
function SHA512_256() {
  if (!(this instanceof SHA512_256))
    return new SHA512_256();

  SHA512.call(this);
  this.h = [
    0x22312194, 0xfc2bf72c,
    0x9f555fa3, 0xc84c64c2,
    0x2393b86b, 0x6f53b151,
    0x96387719, 0x5940eabd,
    0x96283ee2, 0xa88effe3,
    0xbe5e1e25, 0x53863992,
    0x2b0199fc, 0x2c85b8aa,
    0x0eb72ddc, 0x81c52ca2 ];
}
utils.inherits(SHA512_256, SHA512);
module.exports = SHA512_256;

SHA512_256.blockSize = 1024;
SHA512_256.outSize = 256;
SHA512_256.hmacStrength = 192;
SHA512_256.padLength = 128;

SHA512_256.prototype._digest = function digest(enc) {
  if (enc === 'hex')
    return utils.toHex32(this.h.slice(0, 8), 'big');
  else
    return utils.split32(this.h.slice(0, 8), 'big');
};
