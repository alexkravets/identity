'use strict'

const { getKid }             = require('../helpers')
const { EdDSA: { sign } }    = require('@transmute/did-key-ed25519')
const { createPresentation } = require('../helpers')

const signPresentation = async (id, holder, credentials, options) => {
  const vp = createPresentation(id, credentials, holder)

  const {
    nonce,
    domain,
    challenge,
    proofPurpose,
    privateKeyJwk
  } = options

  const created = new Date().getTime()

  const kid = await getKid(holder, proofPurpose)
  const iss = holder
  const sub = holder
  const nbf = created

  const proof = {
    created,
    proofPurpose
  }

  const payload = {
    iss,
    nbf,
    sub,
    vp: {
      ...vp,
      holder,
      proof
    }
  }

  if (id) {
    payload.jti = id
  }

  if (nonce) {
    payload.vp.proof.nonce = nonce
  }

  if (domain) {
    payload.vp.proof.domain = domain
  }

  if (challenge) {
    payload.vp.proof.challenge = challenge
  }

  const token = await sign(payload, privateKeyJwk, {
    alg: 'EdDSA',
    typ: 'JWT',
    kid
  })

  return token
}

module.exports = signPresentation
