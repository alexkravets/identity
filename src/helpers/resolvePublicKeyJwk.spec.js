'use strict'

const crypto     = require('crypto')
const Identity   = require('Identity')
const { expect } = require('chai')
const resolvePublicKeyJwk = require('./resolvePublicKeyJwk')

const SEED_LENGTH = 32
const SEED = crypto.randomBytes(SEED_LENGTH).toString('hex')

describe('helpers/resolvePublicKeyJwk(url)', () => {
  let identity

  before(async () => {
    identity = await Identity.fromSeed(SEED)
  })

  it('returns public key JWK for URL', async () => {
    const didDocument = await identity.getDocument()

    const { id: did } = didDocument
    const [ verificationMethod ] = didDocument.verificationMethod

    const kid = verificationMethod.id

    const publicKeyJwk = await resolvePublicKeyJwk(`${did}${kid}`)
    expect(publicKeyJwk).to.exist
  })

  it('throws error if public key JWK could not be resolved', async () => {
    const { did } = identity

    try {
      await resolvePublicKeyJwk(`${did}#key-1`)

    } catch (error) {
      const message = `Public key "${did}#key-1" is not found`
      expect(error.message).to.equal(message)
      return

    }

    throw new Error('Expected error is not thrown')
  })
})
