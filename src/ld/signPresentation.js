'use strict'

const getVerifiableDigest            = require('./getVerifiableDigest')
const { EdDSA: { signDetached } }    = require('@transmute/did-key-ed25519')
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

  const kid     = await getKid(holder, proofPurpose)
  const did     = holder
  const type    = 'Ed25519Signature2018'
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

  const [ buffer ] = await getVerifiableDigest(verifiablePresentation)
  const proofValue = buffer.toString('hex')

  const jws = await signDetached(buffer, privateKeyJwk, {
    alg:  'EdDSA',
    b64:  false,
    crit: [ 'b64' ]
  })

  return {
    ...verifiablePresentation,
    proof: {
      ...proof,
      jws,
      proofValue
    }
  }
}

module.exports = signPresentation
