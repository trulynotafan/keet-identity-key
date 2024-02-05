const test = require('brittle')
const crypto = require('hypercore-crypto')

const IdentityKey = require('../')
const KeyChain = require('../lib/keychain')

test('basic', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const { root } = IdentityKey.from({ mnemonic })

  const proof = IdentityKey.generate({ mnemonic }, publicKey)
  const auth = IdentityKey.verify(proof)

  t.unlike(auth, null)
  t.alike(auth && auth.publicKey, publicKey)
  t.alike(auth && auth.root, root)
})

test('basic - timestamp fail', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const proof = IdentityKey.generate({ mnemonic }, publicKey)
  const auth = IdentityKey.verify(proof, { timestamp: Date.now() + 1 })

  t.alike(auth, null)
})

test('basic - root fail', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const proof = IdentityKey.generate({ mnemonic }, publicKey)
  const auth = IdentityKey.verify(proof, { root: publicKey })

  t.alike(auth, null)
})

test('basic - device authenticates another device', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const device1 = KeyChain.from({ seed: crypto.randomBytes(32) })
  const device2 = KeyChain.from({ seed: crypto.randomBytes(32) })

  const { root } = IdentityKey.from({ mnemonic })

  const proof1 = IdentityKey.generate({ mnemonic }, device1.publicKey)
  const proof2 = IdentityKey.attest(device2.publicKey, device1, proof1)

  const auth = IdentityKey.verify(proof2)

  t.unlike(auth, null)
  t.alike(auth && auth.publicKey, device2.publicKey)
  t.alike(auth && auth.root, root)
})
