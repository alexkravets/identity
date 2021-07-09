'use strict'

const crypto      = require('crypto')
const Identity    = require('Identity')
const { expect }  = require('chai')
const verifyProof = require('./verifyProof')
const { createAccountCredential } = require('../../node_modules/@kravc/schema/examples')

const ISSUER_SEED = crypto.randomBytes(Identity.SEED_LENGTH).toString('hex')
const HOLDER_SEED = crypto.randomBytes(Identity.SEED_LENGTH).toString('hex')

describe('ld/verifyProof(verifiableInput, signerId)', () => {
  let issuer
  let holder
  let unsignedCredential
  let verifiableCredential

  before(async () => {
    issuer = await Identity.fromSeed(ISSUER_SEED)
    holder = await Identity.fromSeed(HOLDER_SEED)

    unsignedCredential   = createAccountCredential(holder.did, 'Proof')
    verifiableCredential = await issuer.issue(unsignedCredential)
  })

  it('throws an error if signer mismatch', async () => {
    const invalidCredential = JSON.parse(JSON.stringify(verifiableCredential))
    invalidCredential.credentialSubject.username = 'CHANGED'

    try {
      await verifyProof(invalidCredential, 'did:OTHER_ISSUER')

    } catch (error) {
      return expect(error.message).to.eql('Verification method mismatch')

    }

    throw new Error('Error not thrown')
  })

  it('throws an error if credential subject field is changed', async () => {
    const invalidCredential = JSON.parse(JSON.stringify(verifiableCredential))
    invalidCredential.credentialSubject.username = 'CHANGED'

    try {
      await verifyProof(invalidCredential, issuer.did)

    } catch (error) {
      return expect(error.message).to.eql('Proof verification failed')

    }

    throw new Error('Error not thrown')
  })

  it('throws an error if field is added to credential subject', async () => {
    const invalidCredential = JSON.parse(JSON.stringify(verifiableCredential))
    invalidCredential.credentialSubject.other = 'FIELD'

    try {
      await verifyProof(invalidCredential, issuer.did)

    } catch (error) {
      return expect(error.message).to.eql('Proof verification failed')

    }

    throw new Error('Error not thrown')
  })

  it('throws an error if verification failed', async () => {
    const expirationDate    = new Date(new Date().getTime() - 1000).toISOString()
    const expiredCredential = await issuer.issue(unsignedCredential, { expirationDate })

    const verifiableCredential = await issuer.issue(unsignedCredential)
    verifiableCredential.proof.jws = expiredCredential.proof.jws

    try {
      await verifyProof(verifiableCredential, issuer.did)

    } catch (error) {
      return expect(error.message).to.eql('Proof verification failed')

    }

    throw new Error('Error not thrown')
  })

  it('throws an error if unable to verify proof', async () => {
    const verifiableCredential = await issuer.issue(unsignedCredential)

    verifiableCredential.proof.jws = 'HEADER..INVALID_SIGNATURE'

    try {
      await verifyProof(verifiableCredential, issuer.did)

    } catch (error) {
      return expect(error.message).to.include('Unable to verify proof')

    }

    throw new Error('Error not thrown')
  })
})
