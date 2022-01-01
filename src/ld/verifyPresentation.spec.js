'use strict'

const crypto                         = require('crypto')
const Identity                       = require('Identity')
const { expect }                     = require('chai')
const verifyPresentation             = require('./verifyPresentation')
const getVerifiableBuffer            = require('./getVerifiableBuffer')
const { alg, type, signDetached }    = require('../suite')
const { createAccountCredential }    = require('../../node_modules/@kravc/schema/examples')
const { getKid, createPresentation } = require('../helpers')

const randomBytes = length => crypto.randomBytes(length)

describe('ld/verifyPresentation(verifiablePresentation)', () => {
  let issuer
  let holder

  before(async () => {
    issuer = await Identity.generate(randomBytes)
    holder = await Identity.generate(randomBytes)
  })

  it('throws an error if presentation credential holder mismatch', async () => {
    const vc = createAccountCredential('did:OTHER_HOLDER', 'Mismatch')
    const credential = await issuer.issue(vc)

    const vp = createPresentation(undefined, [ credential ], 'did:OTHER_HOLDER')
    const proofPurpose = 'assertionMethod'

    const kid = await getKid(holder.did, proofPurpose)
    const did = holder.did
    const verificationMethod = `${did}${kid}`

    const proof = {
      type,
      proofPurpose,
      verificationMethod
    }

    const verifiablePresentation = {
      holder: holder.did,
      ...vp,
      proof
    }

    const [ verifiableBuffer ] = await getVerifiableBuffer(verifiablePresentation)

    const privateKeyJwk = await holder._keyPair.toJwk(true)
    const jws = await signDetached(verifiableBuffer, privateKeyJwk, {
      b64:  false,
      crit: [ 'b64' ],
      alg
    })

    const mismatchPresentation = {
      ...verifiablePresentation,
      proof: {
        ...proof,
        jws
      }
    }

    try {
      await verifyPresentation(mismatchPresentation)

    } catch (error) {
      return expect(error.message).to.eql('Credential holder mismatch')

    }

    throw new Error('Error not thrown')
  })
})
