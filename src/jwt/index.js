'use strict'

const verify           = require('./verify')
const { decode }       = require('../suite')
const issueCredential  = require('./issueCredential')
const signPresentation = require('./signPresentation')

module.exports = { verify, decode, issueCredential, signPresentation }
