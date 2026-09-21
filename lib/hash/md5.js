'use strict';

// MD5, in the same BlockHash idiom as the SHA and RIPEMD implementations here.
//
// Added for consumers replacing the `create-hash` family, which reaches md5
// through a separate `md5.js` package (unmaintained since 2018) sitting on top
// of `hash-base`. Implementing it here keeps that whole subtree out of their
// dependency trees, since this package has none of its own.
//
// MD5 is cryptographically broken and must not be used where collision
// resistance matters. It remains necessary for interoperability: legacy
// signature algorithms (RSA-MD5) and checksums still call for it.

var utils = require('./utils');
var common = require('./common');

var rotl32 = utils.rotl32;
var sum32 = utils.sum32;
var sum32_4 = utils.sum32_4;
var BlockHash = common.BlockHash;

function MD5() {
  if (!(this instanceof MD5))
    return new MD5();

  BlockHash.call(this);

  this.h = [ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 ];
  this.endian = 'little';
}
utils.inherits(MD5, BlockHash);
exports.md5 = MD5;

MD5.blockSize = 512;
MD5.outSize = 128;
MD5.hmacStrength = 192;
MD5.padLength = 64;

// Per-round left-rotation amounts.
var S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
];

// K[i] = floor(2^32 * abs(sin(i + 1))), as specified in RFC 1321.
var K = [
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
];

MD5.prototype._update = function update(msg, start) {
  var A = this.h[0];
  var B = this.h[1];
  var C = this.h[2];
  var D = this.h[3];

  for (var i = 0; i < 64; i++) {
    var F;
    var g;

    if (i < 16) {
      F = (B & C) | (~B & D);
      g = i;
    } else if (i < 32) {
      F = (D & B) | (~D & C);
      g = (5 * i + 1) % 16;
    } else if (i < 48) {
      F = B ^ C ^ D;
      g = (3 * i + 5) % 16;
    } else {
      F = C ^ (B | ~D);
      g = (7 * i) % 16;
    }

    var tmp = D;
    D = C;
    C = B;
    B = sum32(B, rotl32(sum32_4(A, F, K[i], msg[start + g]), S[i]));
    A = tmp;
  }

  this.h[0] = sum32(this.h[0], A);
  this.h[1] = sum32(this.h[1], B);
  this.h[2] = sum32(this.h[2], C);
  this.h[3] = sum32(this.h[3], D);
};

MD5.prototype._digest = function digest(enc) {
  if (enc === 'hex')
    return utils.toHex32(this.h, 'little');
  else
    return utils.split32(this.h, 'little');
};
