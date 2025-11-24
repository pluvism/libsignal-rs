const crypto = require('./crypto');
const nodeCrypto = require('crypto');

class HKDF {
  HASH_OUTPUT_SIZE = 32;

  deriveSecrets(inputKeyMaterial, info, outputLength, salt = null) {
    salt = salt || Buffer.alloc(this.HASH_OUTPUT_SIZE);
    const prk = this.extract(salt, inputKeyMaterial);
    return this.expand(prk, info, outputLength);
  }

  extract(salt, inputKeyMaterial) {
    const mac = crypto.calculateMAC(inputKeyMaterial, salt);
    return mac;
  }

  expand(prk, info, outputSize) {
    const iterations = Number(Math.ceil(outputSize / this.HASH_OUTPUT_SIZE));
    let mixin = Buffer.alloc(0);
    let results = Buffer.alloc(0);
    let remainingBytes = outputSize;
    for (
      let i = this.getIterationStartOffset();
      i < this.getIterationStartOffset() + iterations;
      i++
    ) {
      const hmac = nodeCrypto.createHmac('sha256', prk);
      hmac.update(mixin);
      if (info) hmac.update(Buffer.from(info));
      hmac.update(Buffer.from(String.fromCharCode(i % 256)));
      const stepResult = hmac.digest();
      const stepSize = Math.min(remainingBytes, stepResult.length);
      results = Buffer.concat([results, stepResult.slice(0, stepSize)]);
      mixin = stepResult;
      remainingBytes -= stepSize;
    }
    return results;
  }

  getIterationStartOffset() {
    return 0;
  }
}

module.exports = HKDF;