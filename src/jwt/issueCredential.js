'use strict'

const { getKid }    = require('../helpers')
const { sign, alg } = require('../suite')

const issueCredential = async (vc, options) => {
  const { issuer, privateKeyJwk, expirationDate } = options

  const kid = await getKid(issuer)
  const iss = issuer
  const jti = vc.id
  const nbf = Math.round(new Date().getTime() / 1000)
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
    payload.exp = Math.round(new Date(expirationDate).getTime() / 1000)
    payload.vc.expirationDate = new Date(expirationDate).toISOString()
  }

  const token = await sign(payload, privateKeyJwk, {
    typ: 'JWT',
    alg,
    kid
  })

  return token
}

module.exports = issueCredential
