'use strict'

// NOTE: Specification reference:
// https://w3c-ccg.github.io/lds-ed25519-2018/
// https://w3c-ccg.github.io/ld-cryptosuite-registry/#ed25519signature2018

const createHash   = require('create-hash')
const { canonize } = require('jsonld')
const { documentLoader } = require('@kravc/schema')

const DIGEST_ALGORITHM = 'sha512'

const getVerifiableDigest = async (verifiableInput) => {
  const { jws: signature, proofValue, ...proof } = verifiableInput.proof

  const verifiableDocument  = { ...verifiableInput, proof }
  const canonizedCredential = await canonize(verifiableDocument, { documentLoader })

  const digest = createHash(DIGEST_ALGORITHM)
    .update(canonizedCredential)
    .digest()

  return [ digest, signature, proofValue ]
}

module.exports = getVerifiableDigest
