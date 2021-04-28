'use strict'

const ld        = require('./ld')
const jwt       = require('./jwt')
const sha256    = require('js-sha256')
const Buffer    = require('safe-buffer').Buffer
const defaults  = require('lodash.defaults')
const validator = require('validator')

const { resolve, isVerifiablePresentation } = require('./helpers')
const { KeyPair, publicKeyUInt8ArrayFromPublicKeyBase58 } = require('./suite')

const SEED_LENGTH = 32

class Identity {
  static get SEED_LENGTH() {
    return SEED_LENGTH
  }

  static get DEFAULT_AUTHORIZATION_TIMEOUT_MS() {
    return 1000 * 30
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

  static async resolvePublicKeyHex(did, methodId = 'authentication') {
    const didDocument = await resolve(did)

    const [ keyId ] = didDocument[methodId]
    const verificationMethod  = didDocument.verificationMethod.find(key => key.id === keyId)
    const { publicKeyBase58 } = verificationMethod

    const recipientPublicKeyHex = publicKeyUInt8ArrayFromPublicKeyBase58(publicKeyBase58)

    return recipientPublicKeyHex
  }

  constructor(keyPair) {
    this._keyPair = keyPair
  }

  get did() {
    const { controller: did } = this._keyPair
    return did
  }

  get publicKey() {
    return this._keyPair.publicKeyBuffer.toString('hex')
  }

  get privateKey() {
    return this._keyPair.privateKeyBuffer.toString('hex')
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

  async createAuthorization(url, body = null, options = {}) {
    const format         = 'jwt'
    const domain         = url
    const expirationDate = Date.now() + Identity.DEFAULT_AUTHORIZATION_TIMEOUT_MS

    const proofOptions = { domain, expirationDate, ...options }

    if (body) {
      proofOptions.challenge = sha256(body)
    }

    const token = await this.createPresentation([], { format, proofOptions })

    return token
  }

  verify(verifiableInput) {
    return Identity.verify(verifiableInput)
  }
}

module.exports = Identity
