'use strict'

const isVerifiablePresentation = object => {
  const { type } = object

  return [].concat(type).includes('VerifiablePresentation')
}

module.exports = isVerifiablePresentation
