'use strict'

const alg  = 'ES256K'
const type = 'EcdsaSecp256k1VerificationKey2019'

const {
  ES256K:   { sign, decode, verify, signDetached, verifyDetached: _verifyDetached },
  driver:   { resolve },
  keyUtils: { publicKeyJwkFromPublicKeyHex, publicKeyUInt8ArrayFromPublicKeyBase58 }
} = require('@transmute/did-key-secp256k1')

const { Secp256k1KeyPair: KeyPair } = require('@transmute/did-key-secp256k1')

const publicKeyJwkFromPublicKeyBase58 = value => {
  const publicKeyHex = publicKeyUInt8ArrayFromPublicKeyBase58(value).toString('hex')
  const publicKeyJwk = publicKeyJwkFromPublicKeyHex(publicKeyHex)

  return publicKeyJwk
}

const verifyDetached = async (jws, credentialDigestBuffer, publicKeyJwk) => {
  try {
    await _verifyDetached(jws, credentialDigestBuffer, publicKeyJwk)

  } catch (error) {
    const isVerificationFailed = error.message.includes('ECDSA Verify Failed')

    if (isVerificationFailed) {
      return false
    }

    throw error
  }

  return true
}

module.exports = {
  alg,
  type,
  sign,
  verify,
  decode,
  KeyPair,
  resolve,
  signDetached,
  verifyDetached,
  publicKeyJwkFromPublicKeyBase58,
  publicKeyUInt8ArrayFromPublicKeyBase58
}
