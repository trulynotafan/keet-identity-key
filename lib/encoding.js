const c = require('compact-encoding')

const ATTESTED_DEVICE = 0
const ATTESTED_DATA = 1

const AttestedDevice = {
  preencode (state, a) {
    c.uint8.preencode(state, ATTESTED_DEVICE)
    c.uint32.preencode(state, a.timestamp)
    c.fixed32.preencode(state, a.root)
    c.fixed32.preencode(state, a.device)
  },
  encode (state, a) {
    c.uint8.encode(state, ATTESTED_DEVICE)
    c.uint32.encode(state, a.timestamp)
    c.fixed32.encode(state, a.root)
    c.fixed32.encode(state, a.device)
  },
  decode (state) {
    throw new Error('Signed data should only be encoded')
  }
}

const AttestedData = {
  preencode (state, a) {
    c.uint8.preencode(state, ATTESTED_DATA)
    c.uint32.preencode(state, a.timestamp)
    c.fixed32.preencode(state, a.root)
    c.fixed32.preencode(state, a.data)
  },
  encode (state, a) {
    c.uint8.encode(state, ATTESTED_DATA)
    c.uint32.encode(state, a.timestamp)
    c.fixed32.encode(state, a.root)
    c.fixed32.encode(state, a.data)
  },
  decode (state) {
    throw new Error('Signed data should only be encoded')
  }
}

const IntermediateProof = {
  preencode (state, proof) {
    c.uint8.preencode(state, ATTESTED_DEVICE)
    if (proof.publicKey) {
      c.fixed32.preencode(state, proof.publicKey)
    }
    c.fixed64.preencode(state, proof.signature)
  },
  encode (state, proof) {
    const type = proof.publicKey ? ATTESTED_DEVICE : ATTESTED_DATA
    c.uint8.encode(state, type)
    if (type === ATTESTED_DEVICE) {
      c.fixed32.encode(state, proof.publicKey)
    }
    c.fixed64.encode(state, proof.signature)
  },
  decode (state) {
    const type = c.uint8.decode(state)
    const publicKey = type === ATTESTED_DEVICE
      ? c.fixed32.decode(state)
      : null

    return {
      publicKey,
      signature: c.fixed64.decode(state)
    }
  }
}

const ProofEncoding = {
  preencode (state, proof) {
    c.uint32.preencode(state, proof.version)
    c.uint32.preencode(state, proof.timestamp)
    c.fixed32.preencode(state, proof.root)
    c.array(IntermediateProof).preencode(state, proof.chain)
  },
  encode (state, proof) {
    c.uint32.encode(state, proof.version)
    c.uint32.encode(state, proof.timestamp)
    c.fixed32.encode(state, proof.root)
    c.array(IntermediateProof).encode(state, proof.chain)
  },
  decode (state) {
    const version = c.uint32.decode(state)
    const timestamp = c.uint32.decode(state)
    const root = c.fixed32.decode(state)
    const chain = c.array(IntermediateProof).decode(state)

    return {
      version,
      timestamp,
      root,
      chain
    }
  }
}

module.exports = {
  AttestedDevice,
  AttestedData,
  ProofEncoding
}
