const c = require('compact-encoding')
const b4a = require('b4a')

const KeyChain = require('./lib/keychain')
const { sign, verify, hash } = require('./lib/crypto')

const {
  ProofEncoding,
  AttestedData,
  AttestedDevice
} = require('./lib/encoding')

const {
  ATTESTED_DEVICE,
  ATTESTED_DATA,
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

    const signable = c.encode(AttestedDevice, publicKey)
    const signature = sign(signable, parent)

    proof.chain.push({
      type: ATTESTED_DEVICE,
      publicKey,
      signature
    })

    return c.encode(ProofEncoding, proof)
  }

  static attestData (attestedData, keyPair, proof) {
    if (attestedData === null) throw new Error('Data is not attestable')

    if (b4a.isBuffer(proof)) {
      proof = c.decode(ProofEncoding, proof)
    }

    const signable = c.encode(AttestedData, hash(attestedData))
    const signature = sign(signable, keyPair)

    proof.chain.push({
      type: ATTESTED_DATA,
      signature
    })

    return c.encode(ProofEncoding, proof)
  }

  static verify (proof, attestedData, opts = {}) {
    if (b4a.isBuffer(proof)) {
      proof = c.decode(ProofEncoding, proof)
    }

    const { version, timestamp, root, chain } = proof

    // validate version
    if (version > VERSION) return null

    // validate attested data
    if (!validateAdditionalData(chain, attestedData)) return null

    // verify timestamp
    if (opts.timestamp) {
      if (timestamp < opts.timestamp) return null
    }

    // verify root
    if (opts.identityPublicKey) {
      if (!b4a.equals(root, opts.identityPublicKey)) return null
    }

    const devicePublicKey = attestedData === null
      ? chain[chain.length - 1].publicKey
      : chain[chain.length - 2].publicKey

    if (opts.devicePublicKey) {
      if (!b4a.equals(devicePublicKey, opts.devicePublicKey)) return null
    }

    let parent = root

    // verify chain
    for (let i = 0; i < chain.length; i++) {
      const { publicKey, signature } = chain[i]

      const signable = publicKey
        ? c.encode(AttestedDevice, publicKey)
        : c.encode(AttestedData, hash(attestedData))

      if (!verify(signable, signature, parent)) {
        return null
      }

      parent = publicKey
    }

    return {
      timestamp,
      identityPublicKey: root,
      devicePublicKey
    }
  }
}

function validateAdditionalData (chain, attestedData) {
  const last = chain[chain.length - 1]

  if (!attestedData && attestedData !== null) return false
  if (attestedData === null && last.publicKey === null) return false
  if (attestedData !== null && last.publicKey !== null) return false

  return true
}
