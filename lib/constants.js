const VERSION = 0

// https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
const BIP43_PURPOSE = 48 // SLIP-48 wallet

// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
const KEET_SLIP44 = 5338

// derivation paths:
//   root          -> m/44'/keet'/0'/1'
//   discoveryKey  -> m/44'/keet'/1'/0'
//   encryptionKey -> m/44'/keet'/1'/1'

const KEET_ROOT_PATH = [BIP43_PURPOSE, KEET_SLIP44, 0, 0]
const KEET_DISCOVERY_PATH = [BIP43_PURPOSE, KEET_SLIP44, 1, 0]
const KEET_ENCRYPTION_PATH = [BIP43_PURPOSE, KEET_SLIP44, 1, 1]

const ATTESTED_DEVICE = 0
const ATTESTED_DATA = 1

module.exports = {
  VERSION,
  ATTESTED_DEVICE,
  ATTESTED_DATA,
  KEET_ROOT_PATH,
  KEET_DISCOVERY_PATH,
  KEET_ENCRYPTION_PATH
}
