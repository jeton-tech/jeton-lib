const bitcore = require('bitcore-lib-cash')
const Address = bitcore.Address
const Hash = bitcore.crypto.Hash
const Script = bitcore.Script
const PublicKey = bitcore.PublicKey

var OutputScript = function (data) {
    
    this.refereePubKey = data.refereePubKey
    this.parties = data.parties
}

OutputScript.prototype.toScript = function () {
    //Output Script
    let outScript = Script()

    // Build the conditionals for the parties
    for(let i = 0; i < this.parties.length; i++) {
        outScript.add(this.buildPartyConditional(i))
        if(i < (this.parties.length - 1) ) {
            outScript.add('OP_ELSE')
        }
    }
    // End the conditionals
    for(let i = 0; i < this.parties.length; i++) {
        outScript.add('OP_ENDIF')
    }

    outScript.add('OP_EQUALVERIFY')
    .add('OP_CHECKSIG')

    return outScript
}


OutputScript.prototype.toBuffer = function () {
    let outScript = this.toScript()
    return outScript.toBuffer()
}


OutputScript.prototype.toScriptHash = function () {
    let outputBuf = this.toBuffer()
    var outputP2SH = new Script()
    .add('OP_HASH160')
    .add(Hash.sha256ripemd160(outputBuf))
    .add('OP_EQUAL')

    return outputP2SH
}


OutputScript.prototype.toAddress = function (network) {
    network = network || 'livenet'
    let address = new Address(this.toScriptHash(), network, 'scripthash')
    return address
}


OutputScript.prototype.buildPartyConditional = function(index) {
    let party = this.parties[index]
    let s = Script()
    .add('OP_DUP')
    .add(Buffer.from(party.message, 'utf-8'))
    .add('OP_EQUAL')
    // If message is player wins
    .add('OP_IF')
        .add('OP_DROP')
        .add(Buffer.from(party.message, 'utf-8'))
        .add(this.refereePubKey.toBuffer())
        .add('OP_CHECKDATASIGVERIFY')
        .add('OP_DUP')
        .add('OP_HASH160')
        .add(party.pubKey.toAddress().hashBuffer)

    return s
}

module.exports = OutputScript