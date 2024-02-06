const sodium = require('sodium-universal')
const b4a = require('b4a')
const assert = require('nanoassert')

module.exports = {
  sign,
  verify,
  hash,
  hmac
}

function sign (signable, keyPair) {
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, signable, keyPair.secretKey)

  return signature
}

function verify (signable, signature, publicKey) {
  return sodium.crypto_sign_verify_detached(signature, signable, publicKey)
}

function hash (data, output = b4a.alloc(64)) {
  sodium.crypto_hash_sha512(output, data)
  return output
}

function hmac (output, data, key) {
  const innerPad = b4a.alloc(128, 0x36)
  const outerPad = b4a.alloc(128, 0x5c)

  bufferXor(innerPad, key)
  bufferXor(outerPad, key)

  const int = b4a.alloc(64)
  hash(b4a.concat([innerPad, data]), int)
  hash(b4a.concat([outerPad, int]), output)

  return output
}

function bufferXor (output, data) {
  assert(output.byteLength >= data.byteLength)

  for (let i = 0; i < data.byteLength; i++) {
    output[i] ^= data[i]
  }

  return output
}
