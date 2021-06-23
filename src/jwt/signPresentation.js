'use strict'

const { sign, alg } = require('../suite')
const { getKid, createPresentation } = require('../helpers')

const signPresentation = async (id, holder, credentials, options) => {
  const vp = createPresentation(id, credentials, holder)

  const {
    nonce,
    domain,
    challenge,
    proofPurpose,
    privateKeyJwk,
    expirationDate
  } = options

  const createdDate = new Date()

  const kid = await getKid(holder, proofPurpose)
  const iss = holder
  const sub = holder
  const nbf = Math.round(createdDate.getTime() / 1000)

  const created = createdDate.toISOString()

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

  if (expirationDate) {
    payload.exp = Math.round(new Date(expirationDate).getTime() / 1000)
  }

  const token = await sign(payload, privateKeyJwk, {
    typ: 'JWT',
    alg,
    kid
  })

  return token
}

module.exports = signPresentation
