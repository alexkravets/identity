'use strict'

const verifyProof   = require('./verifyProof')
const { validator } = require('../helpers')

const verifyCredential = async (verifiableCredential) => {
  validator.validate(verifiableCredential, 'VerifiableCredential')

  const { issuer } = verifiableCredential
  await verifyProof(verifiableCredential, issuer)

  const { expirationDate } = verifiableCredential

  if (expirationDate) {
    const now = new Date()
    const isExpired = new Date(expirationDate) < now

    if (isExpired) {
      throw new Error('Credential expired')
    }
  }

  return verifiableCredential
}

module.exports = verifyCredential
