'use strict';

var jeton = require('bitcore-lib-cash')

// Extensions
jeton.Transaction = require('./lib/Transaction')

// Jeton Specific
jeton.Signature = require('./lib/Signature')

// Escrow
jeton.escrow = {}
jeton.escrow.InputScript = require('./lib/escrow/InputScript')
jeton.escrow.OutputScript = require('./lib/escrow/OutputScript')

module.exports = jeton