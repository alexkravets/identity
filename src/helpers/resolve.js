'use strict'

const { resolve } = require('../suite')

module.exports = async (url) => {
  const { didDocument } = await resolve(url)
  return didDocument
}
