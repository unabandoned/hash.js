'use strict';

// Vendored from minimalistic-assert 1.0.1 (ISC, Copyright 2015 Calvin
// Metcalf — https://github.com/calvinmetcalf/minimalistic-assert), abandoned
// since 2018. Ten lines with no dependencies of its own: cheaper to carry here
// than to depend on, and it takes this package's runtime tree to zero.

module.exports = assert;

function assert(val, msg) {
  if (!val)
    throw new Error(msg || 'Assertion failed');
}

assert.equal = function assertEqual(l, r, msg) {
  if (l != r)
    throw new Error(msg || ('Assertion failed: ' + l + ' != ' + r));
};
