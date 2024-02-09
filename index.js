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
  VERSION,
  KEET_ROOT_PATH,
  IDENTITY_INDEX,
  DISCOVERY_INDEX,
  ENCRYPTION_INDEX
} = require('./lib/constants')

module.exports = class IdentityKey {
  static generateMnemonic () {
    return KeyChain.generateMnemonic()
  }

  static deriveSeed (mnemonic) {
    return KeyChain.deriveSeed(mnemonic)
  }

  static from ({ seed, mnemonic, accountIndex = 0 }) {
    if (accountIndex !== 0) {
      throw new Error('Account recovery is not supported yet')
    }

    const keyPair = KeyChain.from({ seed, mnemonic })

    const path = getBIP48Paths()

    const root = keyPair.get(path.toIdentityKey)
    const discoveryKey = keyPair.get(path.toDiscoveryKey).secretKey.subarray(0, 32)
    const encryptionKey = keyPair.get(path.toEncryptionKey).secretKey.subarray(0, 32)

    return {
      identityPublicKey: root.publicKey,
      discoveryKey,
      encryptionKey
    }
  }

  static bootstrap ({ root, seed, mnemonic, accountIndex = 0 }, device) {
    if (accountIndex !== 0) {
      throw new Error('Account recovery is not supported yet')
    }

    const path = getBIP48Paths()

    if (!root) root = KeyChain.from({ seed, mnemonic }, path.toIdentityKey)

    const proof = {
      version: VERSION,
      timestamp: Date.now(),
      root: root.publicKey,
      chain: []
    }

    return IdentityKey.attestDevice(device, root, proof)
  }

  static attestDevice (publicKey, parent, proof) {
    if (!proof) return IdentityKey.bootstrap({ root: parent }, publicKey)

    if (b4a.isBuffer(proof)) {
      proof = c.decode(ProofEncoding, proof)
    }

    const signable = c.encode(AttestedDevice, {
      timestamp: proof.timestamp,
      root: proof.root,
      device: publicKey
    })

    const signature = sign(signable, parent)

    proof.chain.push({ publicKey, signature })

    return c.encode(ProofEncoding, proof)
  }

  static attestData (attestedData, keyPair, proof) {
    if (attestedData === null) throw new Error('Data is not attestable')

    if (b4a.isBuffer(proof)) {
      proof = c.decode(ProofEncoding, proof)
    }

    if (!proof) {
      proof = {
        version: VERSION,
        timestamp: Date.now(),
        root: keyPair.publicKey,
        chain: []
      }
    }

    const signable = c.encode(AttestedData, {
      timestamp: proof.timestamp,
      root: proof.root,
      data: hash(attestedData)
    })

    const signature = sign(signable, keyPair)

    proof.chain.push({ signature })

    return c.encode(ProofEncoding, proof)
  }

  static verify (proof, attestedData, opts = {}) {
    if (b4a.isBuffer(proof)) {
      proof = c.decode(ProofEncoding, proof)
    }

    if (!validateProof(proof, attestedData, opts)) return null

    const { timestamp, root, chain } = proof

    const candidate = getLastKey(chain) || root

    if (opts.devicePublicKey) {
      if (!b4a.equals(candidate, opts.devicePublicKey)) return null
    }

    const signedData = {
      timestamp,
      root,
      device: null,
      data: attestedData ? hash(attestedData) : null
    }

    let parent = root

    // verify chain
    for (let i = 0; i < chain.length; i++) {
      const { publicKey, signature } = chain[i]

      signedData.device = publicKey

      const enc = publicKey ? AttestedDevice : AttestedData
      const signable = c.encode(enc, signedData)

      if (!verify(signable, signature, parent)) {
        return null
      }

      parent = publicKey
    }

    return {
      timestamp,
      identityPublicKey: root,
      devicePublicKey: candidate
    }
  }
}

function validateProof (proof, attestedData, opts = {}) {
  // validate version
  if (proof.version > VERSION) return false

  // verify timestamp
  if (opts.timestamp) {
    if (proof.timestamp < opts.timestamp) return false
  }

  // verify root
  if (opts.identityPublicKey) {
    if (!b4a.equals(proof.root, opts.identityPublicKey)) return false
  }

  return validateAttestedData(proof.chain, attestedData)
}

function validateAttestedData (chain, attestedData) {
  const last = chain[chain.length - 1]

  if (!attestedData && attestedData !== null) return false
  if (attestedData === null && last.publicKey === null) return false
  if (attestedData !== null && last.publicKey !== null) return false

  return true
}

function getLastKey (chain) {
  const last = chain[chain.length - 1]

  if (last.publicKey) return last.publicKey
  if (chain.length === 1) return null

  return chain[chain.length - 2].publicKey
}

function getBIP48Paths (accountIndex = 0) {
  return {
    toIdentityKey: [...KEET_ROOT_PATH, accountIndex, IDENTITY_INDEX],
    toDiscoveryKey: [...KEET_ROOT_PATH, accountIndex, DISCOVERY_INDEX],
    toEncryptionKey: [...KEET_ROOT_PATH, accountIndex, ENCRYPTION_INDEX]
  }
}
