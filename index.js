const c = require('compact-encoding')
const b4a = require('b4a')

const KeyChain = require('./lib/keychain')
const { sign, verify } = require('./lib/crypto')

const { ProofEncoding } = require('./lib/encoding')

const {
  VERSION,
  KEET_ROOT_PATH,
  KEET_DISCOVERY_PATH,
  KEET_ENCRYPTION_PATH
} = require('./lib/constants')

module.exports = class IdentityKey {
  static generateMnemonic () {
    return KeyChain.generateMnemonic()
  }

  static generateSeed (mnemonic) {
    return KeyChain.generateSeed(mnemonic)
  }

  static from ({ seed, mnemonic }) {
    const keyPair = KeyChain.from({ seed, mnemonic })

    const root = keyPair.get(KEET_ROOT_PATH)

    const discoveryKey = keyPair.get(KEET_DISCOVERY_PATH).secretKey.subarray(0, 32)
    const encryptionKey = keyPair.get(KEET_ENCRYPTION_PATH).secretKey.subarray(0, 32)

    return {
      identityPublicKey: root.publicKey,
      discoveryKey,
      encryptionKey
    }
  }

  static bootstrap ({ root, seed, mnemonic }, device) {
    if (!root) root = KeyChain.from({ seed, mnemonic }, KEET_ROOT_PATH)

    const proof = {
      version: VERSION,
      timestamp: Date.now(),
      root: root.publicKey,
      chain: []
    }

    return IdentityKey.attest(device, root, proof)
  }

  static attest (publicKey, parent, proof) {
    if (!proof) return IdentityKey.bootstrap({ root: parent }, publicKey)

    if (b4a.isBuffer(proof)) {
      proof = c.decode(ProofEncoding, proof)
    }

    const signature = sign(publicKey, parent)

    proof.chain.push({
      publicKey,
      signature
    })

    return c.encode(ProofEncoding, proof)
  }

  static verify (proof, opts = {}) {
    if (b4a.isBuffer(proof)) {
      proof = c.decode(ProofEncoding, proof)
    }

    if (proof.version !== VERSION) return null

    if (opts.timestamp) {
      if (proof.timestamp < opts.timestamp) return null
    }

    if (opts.identityPublicKey) {
      if (!b4a.equals(proof.root, opts.identityPublicKey)) return null
    }

    const last = proof.chain[proof.chain.length - 1]

    if (opts.devicePublicKey) {
      if (!b4a.equals(last.publicKey, opts.devicePublicKey)) return null
    }

    for (let i = proof.chain.length - 1; i >= 0; i--) {
      const { publicKey, signature } = proof.chain[i]
      const parent = i === 0 ? proof.root : proof.chain[i - 1].publicKey

      if (!verify(publicKey, signature, parent)) {
        return null
      }
    }

    return {
      timestamp: proof.timestamp,
      identityPublicKey: proof.root,
      devicePublicKey: last.publicKey
    }
  }
}
