'use strict'

const { Schema, Validator } = require('@kravc/schema')

const proofSchema = new Schema({
  jws:                { required: true },
  type:               { required: true, enum: [ 'Ed25519Signature2018', 'EcdsaSecp256k1VerificationKey2019' ] },
  verificationMethod: { required: true }
}, 'Proof')

const credentialSchema = new Schema({
  issuer: { required: true },
  holder: { required: true },
  proof:  { $ref: 'Proof', required: true }
}, 'VerifiableCredential')

const presentationSchema = new Schema({
  holder: { required: true },
  proof:  { $ref: 'Proof', required: true }
}, 'VerifiablePresentation')

const validator = new Validator([
  proofSchema,
  credentialSchema,
  presentationSchema
])

module.exports = validator
