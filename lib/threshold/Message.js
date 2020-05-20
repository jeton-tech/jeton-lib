const bitcore = require('bitcore-lib-cash')
const Address = bitcore.Address
const Hash = bitcore.crypto.Hash
const ECDSA = bitcore.crypto.ECDSA
const Signature = bitcore.crypto.Signature
const Script = bitcore.Script
const PrivateKey = bitcore.PrivateKey
const PublicKey = bitcore.PublicKey
const ScriptNumber = require('./ScriptNumber')

var Message = function (blockHeight, thresholdValue) {
    
    this.blockHeight = blockHeight
    this.threshold = Math.ceil(thresholdValue)
    this.message = this.createMessage()
}

/**
 * Encode a blockHeight and threshold amount into a byte sequence of 8 bytes (4 bytes per value)
 * This is compatible with the CashScript PriceOracle.ts
 * https://github.com/Bitcoin-com/cashscript/blob/master/examples/PriceOracle.ts
 * 
 * 
 */
Message.prototype.createMessage = function () {
    const lhs = ScriptNumber.encode(this.blockHeight)
    const rhs = ScriptNumber.encode(this.threshold)
    // console.log('encoded blockheight', ScriptNumber.encode(this.blockHeight))
    // console.log('encoded threshold', ScriptNumber.encode(this.threshold))
    return Buffer.concat([lhs, rhs]);
}

Message.signMessage = function(message, privkey){
    return new ECDSA().set({
        hashbuf: Hash.sha256(message),
        privkey: privkey
      }).signRandomK().sig;
}

Message.verifySignature = function(message, sig, pubkey) {
    let msgHash = Hash.sha256(message)
    return ECDSA.verify(msgHash, sig, pubkey)
}

module.exports = Message