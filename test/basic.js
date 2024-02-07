const test = require('brittle')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')

const IdentityKey = require('../')
const KeyChain = require('../lib/keychain')

test('basic', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const { identityPublicKey } = IdentityKey.from({ mnemonic })

  const proof = IdentityKey.bootstrap({ mnemonic }, publicKey)
  const auth = IdentityKey.verify(proof, null)

  t.unlike(auth, null)
  t.alike(auth && auth.devicePublicKey, publicKey)
  t.alike(auth && auth.identityPublicKey, identityPublicKey)
})

test('basic - timestamp fail', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const proof = IdentityKey.bootstrap({ mnemonic }, publicKey)
  const auth = IdentityKey.verify(proof, null, { timestamp: Date.now() + 1 })

  t.alike(auth, null)
})

test('basic - root fail', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const { publicKey } = crypto.keyPair()

  const proof = IdentityKey.bootstrap({ mnemonic }, publicKey)
  const auth = IdentityKey.verify(proof, null, { identityPublicKey: publicKey })

  t.alike(auth, null)
})

test('basic - device authenticates another device', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const device1 = KeyChain.from({ seed: crypto.randomBytes(32) })
  const device2 = KeyChain.from({ seed: crypto.randomBytes(32) })

  const { identityPublicKey } = IdentityKey.from({ mnemonic })

  const proof1 = IdentityKey.bootstrap({ mnemonic }, device1.publicKey)
  const proof2 = IdentityKey.attest(device2.publicKey, device1, proof1)

  const auth = IdentityKey.verify(proof2, null)

  t.unlike(auth, null)
  t.alike(auth && auth.devicePublicKey, device2.publicKey)
  t.alike(auth && auth.identityPublicKey, identityPublicKey)
})

test('basic - device attests data', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const device1 = KeyChain.from({ seed: crypto.randomBytes(32) })
  const attestData = b4a.from('attested data')

  const { identityPublicKey } = IdentityKey.from({ mnemonic })

  const proof1 = IdentityKey.bootstrap({ mnemonic }, device1.publicKey)
  const proof2 = IdentityKey.attestData(attestData, device1, proof1)

  const auth = IdentityKey.verify(proof2, attestData)

  t.unlike(auth, null)
  t.alike(auth && auth.devicePublicKey, device1.publicKey)
  t.alike(auth && auth.identityPublicKey, identityPublicKey)
})

test('basic - attested data fail', function (t) {
  const mnemonic = IdentityKey.generateMnemonic()

  const device1 = KeyChain.from({ seed: crypto.randomBytes(32) })
  const attestData = b4a.from('attested data')

  const proof1 = IdentityKey.bootstrap({ mnemonic }, device1.publicKey)
  const proof2 = IdentityKey.attestData(attestData, device1, proof1)

  const auth = IdentityKey.verify(proof2, b4a.from('not attested data'))

  t.alike(auth, null)
})
