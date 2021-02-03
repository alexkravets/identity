'use strict'

const ld          = require('./ld')
const jwt         = require('./jwt')
const Buffer      = require('safe-buffer').Buffer
const defaults    = require('lodash.defaults')
const validator   = require('validator')
const { KeyPair } = require('./suite')
const { resolve, isVerifiablePresentation } = require('./helpers')

const SEED_LENGTH = 32

class Identity {
  static get SEED_LENGTH() {
    return SEED_LENGTH
  }

  static async fromSeed(seedHex) {
    const keyPair = await KeyPair.generate({
      secureRandom: () => Buffer.from(seedHex, 'hex')
    })

    return new Identity(keyPair)
  }

  static verify(verifiableInput) {
    const isString = typeof verifiableInput === 'string'

    if (isString) {
      const isJwt = validator.isJWT(verifiableInput)

      if (isJwt) {
        return jwt.verify(verifiableInput)
      }

      verifiableInput = JSON.parse(verifiableInput)
    }

    const isPresentation = isVerifiablePresentation(verifiableInput)

    if (isPresentation) {
      return ld.verifyPresentation(verifiableInput)
    }

    return ld.verifyCredential(verifiableInput)
  }

  constructor(keyPair) {
    this._keyPair = keyPair
  }

  get did() {
    const { controller: did } = this._keyPair
    return did
  }

  getDocument() {
    return resolve(this.did)
  }

  async issue(credential, options = {}) {
    const { format, ...issueOptions } = options

    defaults(issueOptions, {
      expirationDate: null
    })

    issueOptions.issuer        = this.did
    issueOptions.privateKeyJwk = await this._keyPair.toJwk(true)

    const isJwt = format === 'jwt'

    if (isJwt) {
      return jwt.issueCredential(credential, issueOptions)
    }

    return ld.issueCredential(credential, issueOptions)
  }

  async createPresentation(credentials, options = {}) {
    const { id, format, proofOptions = {} } = options

    defaults(proofOptions, {
      nonce:        null,
      domain:       null,
      challenge:    null,
      proofPurpose: 'authentication',
    })

    proofOptions.privateKeyJwk = await this._keyPair.toJwk(true)

    const isJwt  = format === 'jwt'
    const holder = this.did

    if (isJwt) {
      return jwt.signPresentation(id, holder, credentials, proofOptions)
    }

    return ld.signPresentation(id, holder, credentials, proofOptions)
  }

  verify(verifiableInput) {
    return Identity.verify(verifiableInput)
  }
}

module.exports = Identity
