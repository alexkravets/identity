'use strict'

const CREDENTIAL_SCHEMA_URI = 'https://www.w3.org/2018/credentials/v1'

const createPresentation = (id, verifiableCredential = [], holder) => {
  const type = 'VerifiablePresentation'

  const presentation = {
    '@context': CREDENTIAL_SCHEMA_URI,
    type
  }

  if (id) {
    presentation.id = id
  }

  const verifiableCredentials = [].concat(verifiableCredential)
  const hasCredentials = verifiableCredentials.length > 0

  if (hasCredentials) {
    const holderMismatchCredentials = verifiableCredentials
      .filter(credential => credential.holder !== holder)

    const isHolderMismatch = holderMismatchCredentials.length > 0

    if (isHolderMismatch) {
      throw new Error('Credential holder mismatch')
    }

    presentation.verifiableCredential = verifiableCredentials
  }

  return presentation
}

module.exports = createPresentation
