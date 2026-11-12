var __getOwnPropNames = Object.getOwnPropertyNames;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

// dep.cjs
var require_dep = __commonJS({
  "dep.cjs"(exports2) {
    exports2.value = 42;
  }
});

// a.cjs
var require_a = __commonJS({
  "a.cjs"(exports2) {
    exports2.answer = require_dep().value;
  }
});

// main.cjs
module.exports = require_a();
