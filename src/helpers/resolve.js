'use strict'

const { driver: { resolve } } = require('@transmute/did-key-ed25519')

module.exports = async (url) => {
  const { didDocument } = await resolve(url)
  return didDocument
}
