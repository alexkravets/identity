'use strict'

const getVerifiableDigest     = require('./getVerifiableDigest')
const { resolvePublicKeyJwk } = require('../helpers')
const { EdDSA: { verifyDetached } } = require('@transmute/did-key-ed25519')

const verifyProof = async (verifiableInput, signerId) => {
  const { proof } = verifiableInput

  const isVerificationMethodMismatch = !proof.verificationMethod.startsWith(signerId)

  if (isVerificationMethodMismatch) {
    throw new Error('Verification method mismatch')
  }

  const publicKeyJwk = await resolvePublicKeyJwk(proof.verificationMethod)

  const [ credentialDigestBuffer, jws, proofValue ] = await getVerifiableDigest(verifiableInput)

  const credentialDigestHex  = credentialDigestBuffer.toString('hex')
  const isProofValueMismatch = credentialDigestHex !== proofValue

  if (isProofValueMismatch) {
    throw new Error('Proof value mismatch')
  }

  let isVerified

  try {
    isVerified = verifyDetached(jws, credentialDigestBuffer, publicKeyJwk)

  } catch (error) {
    throw new Error(`Unable to verify proof: ${error.message}`)

  }

  if (!isVerified) {
    throw new Error('Proof verification failed')
  }
}

module.exports = verifyProof
