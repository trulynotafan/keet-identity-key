const sodium = require('sodium-universal')
const c = require('compact-encoding')
const assert = require('nanoassert')
const b4a = require('b4a')
const { HMAC } = require('@holepunchto/hmac')
const bip39 = require('@holepunchto/bip39')

const { sign } = require('./crypto')

const MASTER_CHAIN_CODE = b4a.from('ed25519 seed')
const HARDENED_OFFSET = 0x80000000

class KeyChain {
  constructor () {
    this._buffer = b4a.alloc(64)

    this.chainKey = this._buffer.subarray(0, 32)
    this.chainCode = this._buffer.subarray(32)

    this.publicKey = b4a.alloc(32)
    this.secretKey = b4a.alloc(64)
  }

  static generateMnemonic () {
    return bip39.generateMnemonic()
  }

  static deriveSeed (mnemonic) {
    return bip39.mnemonicToSeed(mnemonic)
  }

  static from ({ mnemonic, seed }, path) {
    assert(mnemonic || seed, 'No mnemonic or seed was passed.')

    if (mnemonic) seed = KeyChain.deriveSeed(mnemonic)

    const key = new KeyChain()

    HMAC.sha512(seed, MASTER_CHAIN_CODE, key._buffer)

    key._initialise()

    if (!path) return key

    return key.get(path)
  }

  _clone () {
    const key = new KeyChain()

    key.chainKey.set(this.chainKey)
    key.chainCode.set(this.chainCode)
    key._initialise()

    return key
  }

  get isKeychain () {
    return true
  }

  get (path) {
    const key = this._clone()
    key.derive(path)

    return key
  }

  sign (signable) {
    return sign(signable, this)
  }

  derive (path) {
    for (const step of path) {
      const index = ensureHardened(step) // hardened indices are >= 2^31

      HMAC.sha512(encodeDerivationData(this, index), this.chainCode, this._buffer)
      this._initialise()
    }
  }

  _initialise (seed) {
    sodium.crypto_sign_seed_keypair(this.publicKey, this.secretKey, this.chainKey)
  }
}

module.exports = KeyChain

function encodeDerivationData (key, step) {
  const state = { buffer: b4a.alloc(37), start: 0, end: 37 }

  c.uint8.encode(state, 0)
  c.fixed32.encode(state, key.chainKey)
  state.buffer.writeUInt32BE(step, state.start)

  state.buffer[33] |= 0x80

  return state.buffer
}

function ensureHardened (n) {
  if (n >= HARDENED_OFFSET) return n
  return n + HARDENED_OFFSET
}
