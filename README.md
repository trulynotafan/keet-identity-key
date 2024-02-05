# keet-identity-key

Hierarchical keychains that derives deterministic Ed25519 keypairs

```
npm install keypear
```

## Usage

``` js
const IdentityKey = require('@holepunchto/keet-identity-key')

const mnemonic = Identity.generateMnemonic()
const { root } = IdentityKey.from({ mnemonic })

const proof0 = IdentityKey.bootstrap({ mnemonic }, mainDevice.publicKey)
const proof = IdentityKey.attest(auxillaryDevice.publicKey, mainDevice, proof0)

const info = IdentityKey.verify(proof)

if (info === null) {
  // verification failed
} else {
  const { root } = IdentityKey.from({ mnemonic })

  console.log(b4a.equals(info.root, root)) // true
  console.log(b4a.equals(info.publicKey, auxillaryDevice.publicKey)) // true
}
```

## API

#### `mnemonic = IdentityKey.generateMnemonic()`

Generate a new `mnemonic`

#### `seed = IdentityKey.generateSeed(mnemonic)`

Returns a 32-byte buffer with entropy derived from `mnemonic`

#### `keys = IdentityKey.from({ mnemonic, seed })`

Returns `keys` object:
- root
- discoveryKey
- encryption Key

#### `proof = IdentityKey.bootstrap({ seed, mnemonic }, deviceKey)`

Bootstrap an intitial `deviceKey` using a mnemonic

#### `proof = IdentityKey.attest(key, parent, [proof])`

Use an existing `parent` key pair to attest to another `key`.

If provided with a `proof` linking `parent` to a given root key, then the returned proof will link `key` back to the same root key.

#### `info = IdentityKey.verify(proof, { timestamp, root, publicKey })`

Verify a proof.

Returns `null` if verification fails, otherwise an object with:
- timestamp: a timestamp at which the id was bootstrapped
- root: the root public key the proof links to
- publicKey: the public key the proof attests to

Optionally pass any of `timestamp`, `root` or `publicKey`. Verification will fail if:

- proof's timestamp is less than any `timestamp` provided
- proof links back to any key other than `root` provided
- proof attest to any key other than `publicKey` provided

## License

Apache-2.0
