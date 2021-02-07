'use strict'

const crypto     = require('crypto')
const { type }   = require('./suite')
const Identity   = require('./Identity')
const { isJWT }  = require('validator')
const { expect } = require('chai')
const {
  createAccountCredential,
  createMineSweeperScoreCredential
} = require('../node_modules/@kravc/schema/examples')

const HOLDER_SEED   = crypto.randomBytes(Identity.SEED_LENGTH).toString('hex')
const ISSUER_SEED   = crypto.randomBytes(Identity.SEED_LENGTH).toString('hex')
const VERIFIER_SEED = crypto.randomBytes(Identity.SEED_LENGTH).toString('hex')

const createScoreCredential = (issuerId, holderId) => {
  const playerResult = {
    wins:          5,
    losses:        5,
    winRate:       50,
    bestScore:     23450,
    endurance:     'P5M22S',
    dateCreated:   '2020-10-10T00:00:00.000Z',
    bestRoundTime: 10000,
  }

  return createMineSweeperScoreCredential(
    issuerId,
    holderId,
    playerResult
  )
}

describe('Identity', () => {
  let holder
  let issuer
  let verifier

  before(async () => {
    holder   = await Identity.fromSeed(HOLDER_SEED)
    issuer   = await Identity.fromSeed(ISSUER_SEED)
    verifier = await Identity.fromSeed(VERIFIER_SEED)
  })

  describe('Identity.fromSeed(seedHex)', () => {
    it('creates identity instance from seed', async () => {
      expect(holder).to.exist
      expect(holder.did).to.exist
    })
  })

  describe('.resolvePublicKeyHex(did)', () => {
    it('returns public key hex for did', async () => {
      const publicKeyHex = await Identity.resolvePublicKeyHex(holder.did)
      expect(publicKeyHex).to.exist
    })
  })

  describe('Verifiable Credentials', () => {
    let unsignedCredential

    before(async () => {
      unsignedCredential = await createScoreCredential(issuer.did, holder.did)
    })

    describe('JSON-LD', () => {
      describe('.issue(credential, options = {})', () => {
        it('returns signed credential', async () => {
          const signedCredential = await issuer.issue(unsignedCredential)
          expect(signedCredential).to.exist
        })
      })

      describe('.verify(verifiableInput)', () => {
        let verifiableCredential

        before(async () => {
          const expirationDate = new Date(new Date().getTime() + 1000).toISOString()
          verifiableCredential = await issuer.issue(unsignedCredential, { expirationDate })
        })

        it('returns credential if verified', async () => {
          const credential = await verifier.verify(verifiableCredential)
          expect(credential).to.exist
        })

        it('supports credential as stringified JSON', async () => {
          const json = JSON.stringify(verifiableCredential)
          const credential = await verifier.verify(json)
          expect(credential).to.exist
        })

        it('throws an error if expired', async () => {
          const expirationDate = new Date(new Date().getTime() - 1000).toISOString()
          const verifiableCredential = await issuer.issue(unsignedCredential, { expirationDate })

          try {
            await verifier.verify(verifiableCredential)

          } catch (error) {
            return expect(error.message).to.eql('Credential expired')

          }

          throw new Error('Error not thrown')
        })
      })
    })

    describe('JWT', () => {
      describe('.issue(credential, options = {})', () => {
        it('returns signed credential', async () => {
          const token = await issuer.issue(unsignedCredential, { format: 'jwt' })
          expect(isJWT(token)).to.be.true
        })
      })

      describe('.verify(verifiableInput)', () => {
        it('returns payload if verified', async () => {
          const unsignedCredential = await createAccountCredential(holder.did, 'Holder')

          const expirationDate = new Date(new Date().getTime() + 1000).toISOString()
          const token = await issuer.issue(unsignedCredential, { format: 'jwt', expirationDate })

          const payload = await verifier.verify(token)
          expect(payload).to.exist
        })

        it('throws an error if expired', async () => {
          const expirationDate = new Date(new Date().getTime() - 1000).toISOString()
          const token = await issuer.issue(unsignedCredential, { format: 'jwt', expirationDate })

          try {
            await verifier.verify(token)

          } catch (error) {
            return expect(error.message).to.eql('Token expired')

          }

          throw new Error('Error not thrown')
        })
      })
    })
  })

  describe('Verifiable Presentations', () => {
    let credential1
    let credential2

    const nonce     = 'NONCE'
    const domain    = 'example.org'
    const challenge = 'CHALLENGE_ID'

    before(async () => {
      const unsignedCredential1 = await createAccountCredential(holder.did, 'CAHTEP')
      credential1 = await issuer.issue(unsignedCredential1)

      const unsignedCredential2 = await createScoreCredential(issuer.did, holder.did)
      credential2 = await issuer.issue(unsignedCredential2)
    })

    describe('JSON-LD', () => {
      describe('.createPresentation(credentials, options = {})', () => {
        it('returns authentication presentation', async () => {
          const presentation = await holder.createPresentation()
          expect(presentation).to.exist
        })

        it('returns credentials presentation', async () => {
          const presentation = await holder.createPresentation([ credential1, credential2 ])
          expect(presentation).to.exist
        })

        it('throws an error if presentation credential holder mismatch', async () => {
          const vc = createAccountCredential('did:OTHER_HOLDER', 'Mismatch')
          const credential = await issuer.issue(vc)

          try {
            await holder.createPresentation([ credential ])

          } catch (error) {
            return expect(error.message).to.eql('Credential holder mismatch')

          }

          throw new Error('Error not thrown')
        })
      })

      describe('.verify(verifiableInput)', () => {
        it('returns presentation for verified authentication presentation', async () => {
          const verifiablePresentation = await holder.createPresentation([], {
            proofOptions: { challenge, domain, nonce }
          })

          const presentation = await verifier.verify(verifiablePresentation)

          const { proof: { created, jws, proofValue, verificationMethod } } = presentation

          expect(presentation.proof.jws).to.exist
          expect(presentation.proof.proofValue).to.exist
          expect(presentation.proof.verificationMethod).to.exist

          expect(presentation).to.eql({
            '@context': 'https://www.w3.org/2018/credentials/v1',
            type: 'VerifiablePresentation',
            holder: holder.did,
            proof: {
              type,
              created,
              proofPurpose: 'authentication',
              verificationMethod,
              nonce: 'NONCE',
              domain: 'example.org',
              challenge: 'CHALLENGE_ID',
              jws,
              proofValue
            }
          })
        })

        it('returns presentation for verified presentation', async () => {
          const verifiablePresentation = await holder.createPresentation([ credential1, credential2 ])

          const presentation = await verifier.verify(verifiablePresentation)

          expect(presentation).to.exist
          expect(presentation.verifiableCredential).to.have.lengthOf(2)
        })
      })
    })

    describe('JWT', () => {
      describe('.createPresentation(credentials, options = {})', () => {
        it('returns authentication presentation', async () => {
          const token = await holder.createPresentation([], { format: 'jwt' })

          expect(isJWT(token)).to.be.true
        })

        it('returns credentials presentation', async () => {
          const token = await holder.createPresentation([ credential1, credential2 ], {
            format: 'jwt',
            proofOptions: { challenge, domain }
          })

          expect(token).to.exist
        })

        it('throws an error if presentation credential holder mismatch', async () => {
          const vc = createAccountCredential('did:OTHER_HOLDER', 'Mismatch')
          const credential = await issuer.issue(vc)

          try {
            await holder.createPresentation([ credential ], { format: 'jwt' })

          } catch (error) {
            return expect(error.message).to.eql('Credential holder mismatch')

          }

          throw new Error('Error not thrown')
        })
      })

      describe('.verify(verifiableInput)', () => {
        it('returns payload for verified authentication presentation', async () => {
          const token = await holder.createPresentation([], {
            id:     'https://example.com/presentations/PRESENTATION_ID',
            format: 'jwt',
            proofOptions: { challenge, domain, nonce }
          })

          const payload = await verifier.verify(token)
          const { nbf } = payload

          expect(payload).to.eql({
            iss: holder.did,
            jti: 'https://example.com/presentations/PRESENTATION_ID',
            nbf,
            sub: holder.did,
            vp: {
              '@context': 'https://www.w3.org/2018/credentials/v1',
              holder: holder.did,
              id: 'https://example.com/presentations/PRESENTATION_ID',
              proof: {
                challenge: 'CHALLENGE_ID',
                created: nbf,
                domain: 'example.org',
                nonce: 'NONCE',
                proofPurpose: 'authentication'
              },
              type: 'VerifiablePresentation'
            }
          })
        })

        it('returns payload for verified presentation', async () => {
          const token = await holder.createPresentation([ credential1, credential2 ], {
            format: 'jwt',
            proofOptions: { challenge, domain }
          })

          const payload = await verifier.verify(token)

          expect(payload).to.exist
          expect(payload.vp.verifiableCredential).to.have.lengthOf(2)
        })
      })
    })
  })
})
