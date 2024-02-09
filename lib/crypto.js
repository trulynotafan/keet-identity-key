const sodium = require('sodium-universal')
const b4a = require('b4a')

module.exports = {
  sign,
  verify,
  hash: blake2b
}

function sign (signable, keyPair) {
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, signable, keyPair.secretKey)

  return signature
}

function verify (signable, signature, publicKey) {
  return sodium.crypto_sign_verify_detached(signature, signable, publicKey)
}

function blake2b (data, output = b4a.alloc(32)) {
  sodium.crypto_generichash(output, data)
  return output
}
