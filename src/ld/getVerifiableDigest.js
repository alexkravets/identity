'use strict'

// NOTE: Specification reference:
// https://w3c-ccg.github.io/lds-ed25519-2018/
// https://w3c-ccg.github.io/ld-cryptosuite-registry/#ed25519signature2018

const Buffer       = require('safe-buffer').Buffer
const { sha512 }   = require('js-sha512')
const { canonize } = require('jsonld')
const { documentLoader } = require('@kravc/schema')

const getVerifiableDigest = async (verifiableInput) => {
  const { jws: signature, proofValue, ...proof } = verifiableInput.proof

  const verifiableDocument  = { ...verifiableInput, proof }
  const canonizedCredential = await canonize(verifiableDocument, { documentLoader })

  const digestHex = sha512(canonizedCredential)
  const digest = Buffer.from(digestHex)

  return [ digest, signature, proofValue ]
}

module.exports = getVerifiableDigest
