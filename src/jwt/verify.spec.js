'use strict'

const crypto        = require('crypto')
const Identity      = require('Identity')
const { expect }    = require('chai')
const { sign, alg } = require('../suite')
const { createAccountCredential }    = require('../../node_modules/@kravc/schema/examples')
const { getKid, createPresentation } = require('../helpers')

const ISSUER_SEED   = crypto.randomBytes(Identity.SEED_LENGTH).toString('hex')
const HOLDER_SEED   = crypto.randomBytes(Identity.SEED_LENGTH).toString('hex')
const VERIFIER_SEED = crypto.randomBytes(Identity.SEED_LENGTH).toString('hex')

describe('jwt/verify(token)', () => {
  let issuer
  let holder
  let verifier

  before(async () => {
    issuer   = await Identity.fromSeed(ISSUER_SEED)
    holder   = await Identity.fromSeed(HOLDER_SEED)
    verifier = await Identity.fromSeed(VERIFIER_SEED)
  })

  it('throws an error if invalid token payload', async () => {
    const iss = holder.did
    const kid = await getKid(holder.did)

    const payload = {
      iss
    }

    const privateKeyJwk = await holder._keyPair.toJwk(true)
    const invalidToken = await sign(payload, privateKeyJwk, {
      typ: 'JWT',
      alg,
      kid
    })

    try {
      await verifier.verify(invalidToken)

    } catch (error) {
      return expect(error.message).to.eql('Invalid token payload')

    }

    throw new Error('Error not thrown')
  })

  it('throws an error if credential issuer mismatch', async () => {
    const vc = createAccountCredential('did:HOLDER', 'Mismatch')

    const iss = issuer.did
    const kid = await getKid(issuer.did)

    const payload = {
      iss,
      vc: { ...vc, issuer: 'OTHER_ISSUER' }
    }

    const privateKeyJwk = await issuer._keyPair.toJwk(true)
    const mismatchToken = await sign(payload, privateKeyJwk, {
      typ: 'JWT',
      alg,
      kid
    })

    try {
      await verifier.verify(mismatchToken)

    } catch (error) {
      return expect(error.message).to.eql('Credential issuer mismatch')

    }

    throw new Error('Error not thrown')
  })

  it('throws an error if presentation holder mismatch', async () => {
    const vp = createPresentation()

    const iss = holder.did
    const kid = await getKid(holder.did)

    const payload = {
      iss,
      vp: { ...vp, holder: 'OTHER_HOLDER' }
    }

    const privateKeyJwk = await holder._keyPair.toJwk(true)
    const mismatchToken = await sign(payload, privateKeyJwk, {
      typ: 'JWT',
      alg,
      kid
    })

    try {
      await verifier.verify(mismatchToken)

    } catch (error) {
      return expect(error.message).to.eql('Presentation holder mismatch')

    }

    throw new Error('Error not thrown')
  })

  it('throws an error if presentation credential holder mismatch', async () => {
    const vc = createAccountCredential('did:OTHER_HOLDER', 'Mismatch')
    const credential = await issuer.issue(vc)

    const vp = createPresentation(undefined, [ credential ], 'did:OTHER_HOLDER')

    const iss = holder.did
    const kid = await getKid(holder.did)

    const payload = {
      iss,
      vp: { ...vp, holder: iss }
    }

    const privateKeyJwk = await holder._keyPair.toJwk(true)
    const mismatchToken = await sign(payload, privateKeyJwk, {
      typ: 'JWT',
      alg,
      kid
    })

    try {
      await verifier.verify(mismatchToken)

    } catch (error) {
      return expect(error.message).to.eql('Credential holder mismatch')

    }

    throw new Error('Error not thrown')
  })
})
