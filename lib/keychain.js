const sodium = require('libsodium-wrappers')  //universal approach 
const c = require('compact-encoding')
const assert = require('nanoassert')
const b4a = require('b4a')
const { HMAC } = require('sodium-hmac') 
const bip39 = require('bip39-mnemonic')

const { sign } = require('crypto')

const MASTER_CHAIN_CODE = b4a.from('ed25519 seed')
const MASTER_SYMMETRIC_CODE = b4a.from('Symmetric key seed')

const HARDENED_OFFSET = 0x80000000

class KeyChain {
  constructor (seed) {
    this.seed = seed

    this._buffer = b4a.alloc(64)

    this.chainKey = this._buffer.subarray(0, 32)
    this.chainCode = this._buffer.subarray(32)

    this.publicKey = new Uint8Array(sodium.crypto_sign_PUBLICKEYBYTES)
    this.secretKey = new Uint8Array(sodium.crypto_sign_SECRETKEYBYTES)

    this._initialise()
  }

  static generateMnemonic () {
    return bip39.generateMnemonic()
  }

  static deriveSeed (mnemonic) {
    return bip39.mnemonicToSeed(mnemonic)
  }

  static async from ({ mnemonic, seed }, path) {
    await sodium.ready
    
    assert(mnemonic || seed, 'No mnemonic or seed was passed.')

    if (!seed) seed = await KeyChain.deriveSeed(mnemonic)

    const key = new KeyChain(seed)

    if (!path) return key

    return key.get(path)
  }

  getSymmetricKey (path) {
    const buffer = b4a.alloc(64)

    const chainKey = buffer.subarray(0, 32)
    const key = buffer.subarray(32)

    HMAC.sha512(this.seed, MASTER_SYMMETRIC_CODE, buffer)

    for (const step of path) {
      const label = b4a.alloc(step.length + 1)
      b4a.write(label, step, 1, 'utf8')

      HMAC.sha512(label, chainKey, buffer)
    }

    return key
  }

  get isKeychain () {
    return true
  }

  _initialise () {
    HMAC.sha512(this.seed, MASTER_CHAIN_CODE, this._buffer)
    

    const keyPair = sodium.crypto_sign_seed_keypair(this.chainKey)
    
    this.publicKey.set(keyPair.publicKey)
    this.secretKey.set(keyPair.privateKey)
  }

  clear () {
    this.secretKey.fill(0)
    this.chainKey.fill(0)
    this.chainCode.fill(0)
  }

  get (path) {
    return this.derive(path)
  }

  sign (signable) {
    return sign(signable, this)
  }

  derive (path) {
    const buffer = b4a.from(this._buffer)

    const chainKey = buffer.subarray(0, 32)
    const chainCode = buffer.subarray(32)

    for (const step of path) {
      const index = ensureHardened(step) 
      HMAC.sha512(encodeDerivationData(chainKey, index), chainCode, buffer)
    }

    return createKeyPair(chainKey)
  }
}

module.exports = KeyChain

function createKeyPair (seed) {
  if (!seed) throw new Error('No seed provided')

  const keyPair = sodium.crypto_sign_seed_keypair(seed)
  
  return {
    publicKey: new Uint8Array(keyPair.publicKey),
    secretKey: new Uint8Array(keyPair.privateKey)
  }
}

// Browser-compatible version of encodeDerivationData
function encodeDerivationData (key, step) {
  const buffer = b4a.alloc(37)
  let offset = 0

  buffer[offset++] = 0

  for (let i = 0; i < 32; i++) {
    buffer[offset++] = key[i]
  }

  buffer[offset++] = (step >>> 24) & 0xFF
  buffer[offset++] = (step >>> 16) & 0xFF
  buffer[offset++] = (step >>> 8) & 0xFF
  buffer[offset++] = step & 0xFF

  buffer[33] |= 0x80

  return buffer
}

function ensureHardened (n) {
  if (n >= HARDENED_OFFSET) return n
  return n + HARDENED_OFFSET
}
