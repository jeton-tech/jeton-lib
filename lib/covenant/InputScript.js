const bitcore = require('bitcore-lib-cash')
const Hash = bitcore.crypto.Hash
const Script = bitcore.Script
const PublicKey = bitcore.PublicKey


/**
 * Instantiate an object to create escrow scriptSig
 *
 * @param {object} data - The encoded data in various formats
 * @param {Script[]} data.sigScripts - Array of P2PKH signatures for the transaction, in proper order
 * @param {Script} data.outputScript - The original (non-P2SH) scriptPubKey for this input
 * 
 * @constructor
 */
var InputScript = function (data) {
    
    this.sigScripts = data.sigScripts
    this.outputScript = data.outputScript
    this.preimage = data.preimage
}


/**
 * @returns {Script}
 */
InputScript.prototype.toScript = function () {
    let outputBuf = this.outputScript.toBuffer()
    let inScript = Script()
    .add(this.preimage.outputs)
    .add(this.preimage.preimage)
    for (let i = this.sigScripts.length - 1; i >=0; i--) {
        inScript.add(this.sigScripts[i])
    }
    inScript.add(outputBuf)

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