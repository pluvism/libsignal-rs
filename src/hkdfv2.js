const HKDF = require('./hkdf');

class HKDFv3 extends HKDF {
  getIterationStartOffset() {
    return 0;
  }
}
module.exports = HKDFv3;