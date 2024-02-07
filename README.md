# keet-identity-key

Hierarchical keychains that derives deterministic Ed25519 keypairs

```
npm install keypear
```

## Usage

``` js
const IdentityKey = require('@holepunchto/keet-identity-key')

const mnemonic = Identity.generateMnemonic()
const { identityPublicKey } = IdentityKey.from({ mnemonic })

const proof0 = IdentityKey.bootstrap({ mnemonic }, mainDevice.publicKey)
const proof = IdentityKey.attest(auxillaryDevice.publicKey, mainDevice, proof0)

const info = IdentityKey.verify(proof)

if (info === null) {
  // verification failed
} else {
  console.log(b4a.equals(info.identityPublicKey, identityPublicKey)) // true
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

#### `info = IdentityKey.verify(proof, opts ={ timestamp, identityPublicKey, devicePublicKey })`

Verify a proof.

Returns `null` if verification fails, otherwise an object with:
- `timestamp`: a timestamp at which the id was bootstrapped
- `identityPublicKey`: the root public key the proof links to
- `devicePublicKey`: the public key the proof attests to

Optionally pass any of `timestamp`, `identityPublicKey` or `devicePublicKey`. Verification will fail if:

- proof's timestamp is less than any `timestamp` provided
- proof links back to any key other than `identityPublicKey` provided
- proof attests to any key other than `devicePublicKey` provided

## License

Apache-2.0
