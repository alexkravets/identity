'use strict'

const resolve = require('./resolve')

module.exports = async (issuer, proofPurpose = 'assertionMethod') => {
  const didDocument = await resolve(issuer)
  const [ kid ] = didDocument[proofPurpose]

  return kid
}
