const c = require('compact-encoding')

const IntermediateProof = {
  preencode (state, proof) {
    c.fixed32.preencode(state, proof.publicKey)
    c.fixed64.preencode(state, proof.signature)
  },
  encode (state, proof) {
    c.fixed32.encode(state, proof.publicKey)
    c.fixed64.encode(state, proof.signature)
  },
  decode (state) {
    return {
      publicKey: c.fixed32.decode(state),
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

module.exports = { ProofEncoding }
