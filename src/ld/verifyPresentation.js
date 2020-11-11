'use strict'

const verifyProof      = require('./verifyProof')
const { validator }    = require('../helpers')
const verifyCredential = require('./verifyCredential')

const verifyPresentation = async (verifiablePresentation) => {
  validator.validate(verifiablePresentation, 'VerifiablePresentation')

  const { holder } = verifiablePresentation
  await verifyProof(verifiablePresentation, holder)

  const { verifiableCredential: verifiableCredentials = [] } = verifiablePresentation

  for (const verifiableCredential of verifiableCredentials) {
    const isHolderMismatch = holder !== verifiableCredential.holder

    if (isHolderMismatch) {
      throw new Error('Credential holder mismatch')
    }

    await verifyCredential(verifiableCredential)
  }

  return verifiablePresentation
}

module.exports = verifyPresentation
