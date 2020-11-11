'use strict'

const verifyCredential        = require('../ld/verifyCredential')
const { resolvePublicKeyJwk } = require('../helpers')
const { EdDSA: { decode, verify } } = require('@transmute/did-key-ed25519')

module.exports = async (token) => {
  const { header: { kid }, payload: { iss: issuer } } = await decode(token, { complete: true })

  const verificationMethod = `${issuer}${kid}`
  const publicKeyJwk = await resolvePublicKeyJwk(verificationMethod)

  const payload = await verify(token, publicKeyJwk)

  const { exp, iss, vp, vc } = payload

  if (exp) {
    const now = new Date()
    const isExpired = new Date(exp) < now

    if (isExpired) {
      throw new Error('Token expired')
    }
  }

  if (vc) {
    const isIssuerMismatch = iss !== vc.issuer

    if (isIssuerMismatch) {
      throw new Error('Credential issuer mismatch')
    }

    return payload
  }

  if (vp) {
    const isHolderMismatch = iss !== vp.holder

    if (isHolderMismatch) {
      throw new Error('Presentation holder mismatch')
    }

    const { verifiableCredential: verifiableCredentials = [] } = vp

    for (const verifiableCredential of verifiableCredentials) {
      const isHolderMismatch = iss !== verifiableCredential.holder

      if (isHolderMismatch) {
        throw new Error('Credential holder mismatch')
      }

      await verifyCredential(verifiableCredential)
    }

    return payload
  }

  throw new Error('Invalid token payload')
}
