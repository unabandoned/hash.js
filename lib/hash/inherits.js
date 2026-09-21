'use strict';

// Vendored from inherits 2.0.4 (ISC, Copyright Isaac Z. Schlueter —
// https://github.com/isaacs/inherits), abandoned since 2019. This is its
// browser implementation, which is also what Node has needed since Object.create
// became universal, so the package's node/browser split is collapsed to the one
// path. Carrying it here takes this package's runtime tree to zero.

module.exports = function inherits(ctor, superCtor) {
  if (superCtor) {
    ctor.super_ = superCtor;
    ctor.prototype = Object.create(superCtor.prototype, {
      constructor: {
        value: ctor,
        enumerable: false,
        writable: true,
        configurable: true
      }
    });
  }
};
