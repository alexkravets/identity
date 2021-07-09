'use strict'

const getVerifiableBuffer            = require('./getVerifiableBuffer')
const { alg, type, signDetached }    = require('../suite')
const { getKid, createPresentation } = require('../helpers')

const signPresentation = async (id, holder, credentials, options) => {
  const vp = createPresentation(id, credentials, holder)

  const {
    nonce,
    domain,
    challenge,
    proofPurpose,
    privateKeyJwk
  } = options

  const kid = await getKid(holder, proofPurpose)
  const did = holder
  const created = new Date().toISOString()
  const verificationMethod = `${did}${kid}`

  const proof = {
    type,
    created,
    proofPurpose,
    verificationMethod
  }

  if (nonce) {
    proof.nonce = nonce
  }

  if (domain) {
    proof.domain = domain
  }

  if (challenge) {
    proof.challenge = challenge
  }

  const verifiablePresentation = {
    ...vp,
    holder,
    proof
  }

  const [ verifiableBuffer ] = await getVerifiableBuffer(verifiablePresentation)

  const jws = await signDetached(verifiableBuffer, privateKeyJwk, {
    b64:  false,
    crit: [ 'b64' ],
    alg
  })

  return {
    ...verifiablePresentation,
    proof: {
      ...proof,
      jws
    }
  }
}

module.exports = signPresentation
