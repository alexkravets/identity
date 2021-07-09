'use strict'

const Buffer       = require('safe-buffer').Buffer
const { canonize } = require('jsonld')
const { documentLoader } = require('@kravc/schema')

const getVerifiableBuffer = async (verifiableInput) => {
  const { jws: signature, ...proof } = verifiableInput.proof

  const verifiableDocument  = { ...verifiableInput, proof }
  const canonizedCredential = await canonize(verifiableDocument, { documentLoader })

  const buffer = Buffer.from(canonizedCredential)

  return [ buffer, signature ]
}

module.exports = getVerifiableBuffer
