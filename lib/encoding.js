const c = require('compact-encoding')

const { ATTESTED_DEVICE, ATTESTED_DATA } = require('./constants')

const AttestedDevice = {
  preencode (state, data) {
    c.uint8.preencode(state, ATTESTED_DEVICE)
    c.fixed32.preencode(state, data)
  },
  encode (state, data) {
    c.uint8.encode(state, ATTESTED_DEVICE)
    c.fixed32.encode(state, data)
  },
  decode (state) {
    const namespace = c.uint8.decode(state)
    if (namespace !== ATTESTED_DEVICE) throw new Error('Device is not attestable')

    return c.fixed32.decode(state)
  }
}

const AttestedData = {
  preencode (state, data) {
    c.uint8.preencode(state, ATTESTED_DATA)
    c.fixed32.preencode(state, data)
  },
  encode (state, data) {
    c.uint8.encode(state, ATTESTED_DATA)
    c.fixed32.encode(state, data)
  },
  decode (state) {
    const namespace = c.uint8.decode(state)
    if (namespace !== ATTESTED_DATA) throw new Error('Data is not attestable')

    return c.fixed32.decode(state)
  }
}

const IntermediateProof = {
  preencode (state, proof) {
    c.uint8.preencode(state, proof.type)
    if (proof.type === ATTESTED_DEVICE) {
      c.fixed32.preencode(state, proof.publicKey)
    }
    c.fixed64.preencode(state, proof.signature)
  },
  encode (state, proof) {
    c.uint8.encode(state, proof.type)
    if (proof.type === ATTESTED_DEVICE) {
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
      type,
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
