const VERSION = 0

// https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
const BIP43_PURPOSE = 48 // SLIP-48 wallet

// https://github.com/satoshilabs/slips/blob/master/slip-0048.md
const KEET_SLIP48 = 5338
const KEET_ROLE = 0 // owner

// derivation paths:
//   root          -> m/48'/keet'/0'/1'
//   discoveryKey  -> m/48'/keet'/1'/0'
//   encryptionKey -> m/48'/keet'/1'/1'

const KEET_ROOT_PATH = [BIP43_PURPOSE, KEET_SLIP48, KEET_ROLE]

const IDENTITY_INDEX = 0
const DISCOVERY_INDEX = 1
const ENCRYPTION_INDEX = 2

const ATTESTED_DEVICE = 0
const ATTESTED_DATA = 1

module.exports = {
  VERSION,
  ATTESTED_DEVICE,
  ATTESTED_DATA,
  KEET_ROOT_PATH,
  IDENTITY_INDEX,
  DISCOVERY_INDEX,
  ENCRYPTION_INDEX
}
