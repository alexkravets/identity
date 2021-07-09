'use strict'

const { getKid } = require('../helpers')
const { alg, type, signDetached } = require('../suite')

const getVerifiableBuffer = require('./getVerifiableBuffer')

const issueCredential = async (credential, options) => {
  const { issuer, privateKeyJwk, expirationDate } = options

  const issuanceDate = new Date().toISOString()
  const proofPurpose = 'assertionMethod'

  const kid = await getKid(issuer, proofPurpose)
  const did = issuer

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

  const [ verifiableBuffer ] = await getVerifiableBuffer(verifiableCredential)

  const jws = await signDetached(verifiableBuffer, privateKeyJwk, {
    b64:  false,
    crit: [ 'b64' ],
    alg
  })

  return {
    ...verifiableCredential,
    proof: {
      ...proof,
      jws
    }
  }
}

module.exports = issueCredential
