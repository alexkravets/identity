'use strict'

const alg  = 'ES256K'
const type = 'EcdsaSecp256k1VerificationKey2019'

const {
  ES256K:   { sign, decode, verify: _verify, signDetached, verifyDetached },
  driver:   { resolve },
  keyUtils: { publicKeyJwkFromPublicKeyBase58, publicKeyUInt8ArrayFromPublicKeyBase58 }
} = require('@transmute/did-key-secp256k1')

const { Secp256k1KeyPair: { generate } } = require('@transmute/did-key-secp256k1')

// TODO: https://github.com/transmute-industries/did-key.js/issues/63
const verify = async (...args) => {
  const isVerified = await _verify(...args)

  /* istanbul ignore next: to be resolved when new version of crypto suite is released */
  if (!isVerified) {
    throw Error('Token verification failed')
  }

  const { payload } = await decode(args[0], { complete: true })

  return payload
}

module.exports = {
  alg,
  type,
  sign,
  verify,
  decode,
  resolve,
  generate,
  signDetached,
  verifyDetached,
  publicKeyJwkFromPublicKeyBase58,
  publicKeyUInt8ArrayFromPublicKeyBase58
}
