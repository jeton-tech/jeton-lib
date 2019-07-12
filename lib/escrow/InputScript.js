const bitcore = require('bitcore-lib-cash')
const Hash = bitcore.crypto.Hash
const Script = bitcore.Script
const PublicKey = bitcore.PublicKey

var InputScript = function (data) {
    
    this.refereeSig = data.refereeSig
    this.message = data.message
    this.winnerScript = data.winnerScript
    this.outputScript = data.outputScript
}


InputScript.prototype.toScript = function () {
    let outputBuf = this.outputScript.toBuffer()
    let inScript = Script()
    .add(this.winnerScript)
    .add(this.refereeSig.toBuffer())
    .add(Buffer.from(this.message, 'utf-8'))
    .add(outputBuf)

    return inScript
}


InputScript.prototype.toBuffer = function () {
    let outScript = this.toScript()
    return outScript.toBuffer()
}

module.exports = InputScript