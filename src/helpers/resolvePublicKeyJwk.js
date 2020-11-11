'use strict'

const {
  driver:   { resolve },
  keyUtils: { publicKeyJwkFromPublicKeyBase58 }
} = require('@transmute/did-key-ed25519')

const resolvePublicKeyJwk = async (url) => {
  const [ did, keyId ] = url.split('#')
  const kid = `#${keyId}`

  const { didDocument } = await resolve(did)
  const verificationMethod = didDocument.verificationMethod.find(({ id }) => id === kid)

  if (!verificationMethod) {
    throw new Error(`Public key "${did}${kid}" is not found`)
  }

  const { publicKeyBase58 } = verificationMethod
  const jwk = publicKeyJwkFromPublicKeyBase58(publicKeyBase58)

  return jwk
}

module.exports = resolvePublicKeyJwk
