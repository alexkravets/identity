'use strict'

const { verifyDetached }      = require('../suite')
const getVerifiableBuffer     = require('./getVerifiableBuffer')
const { resolvePublicKeyJwk } = require('../helpers')

const verifyProof = async (verifiableInput, signerId) => {
  const { proof } = verifiableInput

  const isVerificationMethodMismatch = !proof.verificationMethod.startsWith(signerId)

  if (isVerificationMethodMismatch) {
    throw new Error('Verification method mismatch')
  }

  const publicKeyJwk = await resolvePublicKeyJwk(proof.verificationMethod)
  const [ credentialVerifiableBuffer, jws ] = await getVerifiableBuffer(verifiableInput)

  let isVerified

  try {
    isVerified = await verifyDetached(jws, credentialVerifiableBuffer, publicKeyJwk)

  } catch (error) {
    throw new Error(`Unable to verify proof: ${error.message}`)

  }

  if (!isVerified) {
    throw new Error('Proof verification failed')
  }
}

module.exports = verifyProof
