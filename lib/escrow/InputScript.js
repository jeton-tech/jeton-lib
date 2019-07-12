const bitcore = require('bitcore-lib-cash')
const Hash = bitcore.crypto.Hash
const Script = bitcore.Script
const PublicKey = bitcore.PublicKey


/**
 * Instantiate an object to create escrow scriptSig
 *
 * @param {object} data - The encoded data in various formats
 * @param {Signature} data.refereeSig
 * @param {string} data.message
 * @param {Script} data.winnerScript - a P2PKH scriptSig for the transaction signed by escrow beneficiary
 * @param {Script} data.outputScript - The original (non-P2SH) scriptPubKey for this input
 * 
 * @constructor
 */
var InputScript = function (data) {
    
    this.refereeSig = data.refereeSig
    this.message = data.message
    this.winnerScript = data.winnerScript
    this.outputScript = data.outputScript
}


/**
 * @returns {Script}
 */
InputScript.prototype.toScript = function () {
    let outputBuf = this.outputScript.toBuffer()
    let inScript = Script()
    .add(this.winnerScript)
    .add(this.refereeSig.toBuffer())
    .add(Buffer.from(this.message, 'utf-8'))
    .add(outputBuf)

    return inScript
}


/**
 * @returns {Buffer}
 */
InputScript.prototype.toBuffer = function () {
    let outScript = this.toScript()
    return outScript.toBuffer()
}

module.exports = InputScript