'use strict';

var jeton = require('bitcore-lib-cash')

// Extensions
jeton.Transaction = require('./lib/Transaction')

// Jeton Specific
jeton.Signature = require('./lib/Signature')

// Escrow
jeton.escrow = require('./lib/escrow')
// jeton.escrow.InputScript = require('./lib/escrow/InputScript')
// jeton.escrow.OutputScript = require('./lib/escrow/OutputScript')

// Threshold
jeton.threshold = require('./lib/threshold')
//jeton.escrow.InputScript = require('./lib/escrow/InputScript')
//jeton.escrow.OutputScript = require('./lib/escrow/OutputScript')

// Covenant
jeton.covenant = require('./lib/covenant')

module.exports = jeton