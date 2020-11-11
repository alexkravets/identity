'use strict'

const { getKid } = require('../helpers')
const { EdDSA: { sign } } = require('@transmute/did-key-ed25519')

const issueCredential = async (vc, options) => {
  const { issuer, privateKeyJwk, expirationDate } = options

  const kid = await getKid(issuer)
  const iss = issuer
  const jti = vc.id
  const nbf = new Date().getTime()
  const sub = vc.credentialSubject.id

  const issuanceDate = new Date(nbf).toISOString()
  const payload = {
    iss,
    sub,
    jti,
    nbf,
    vc: {
      ...vc,
      issuer,
      issuanceDate
    }
  }

  if (expirationDate) {
    payload.exp = new Date(expirationDate).getTime()
    payload.vc.expirationDate = new Date(expirationDate).toISOString()
  }

  const token = await sign(payload, privateKeyJwk, {
    alg: 'EdDSA',
    typ: 'JWT',
    kid
  })

  return token
}

module.exports = issueCredential
