'use strict'

const { getKid } = require('../helpers')
const { EdDSA: { signDetached } } = require('@transmute/did-key-ed25519')

const getVerifiableDigest = require('./getVerifiableDigest')

const issueCredential = async (credential, options) => {
  const { issuer, privateKeyJwk, expirationDate } = options

  const issuanceDate = new Date().toISOString()
  const proofPurpose = 'assertionMethod'

  const kid  = await getKid(issuer, proofPurpose)
  const did  = issuer
  const type = 'Ed25519Signature2018'

  const verificationMethod = `${did}${kid}`

  const proof = {
    created: issuanceDate,
    type,
    proofPurpose,
    verificationMethod
  }

  const verifiableCredential = {
    ...credential,
    issuanceDate,
    issuer,
    proof
  }

  if (expirationDate) {
    verifiableCredential.expirationDate = new Date(expirationDate).toISOString()
  }

  const [ buffer ] = await getVerifiableDigest(verifiableCredential)
  const proofValue = buffer.toString('hex')

  const jws = await signDetached(buffer, privateKeyJwk, {
    alg:  'EdDSA',
    b64:  false,
    crit: [ 'b64' ]
  })

  return {
    ...verifiableCredential,
    proof: {
      ...proof,
      jws,
      proofValue
    }
  }
}

module.exports = issueCredential
