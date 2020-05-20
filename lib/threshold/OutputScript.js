const bitcore = require('bitcore-lib-cash')
const Address = bitcore.Address
const Hash = bitcore.crypto.Hash
const Script = bitcore.Script
const PublicKey = bitcore.PublicKey
const Message = require('./Message')
const ScriptNumber = require('./ScriptNumber')


/**
 * Instantiate an object to create threshold escrow scriptPubKey
 *
 * @param {object} data - The encoded data in various formats
 * @param {PublicKey} data.oraclePubKey
 * @param {int} data.threshold
 * @param {object} data.parties - Parties object
 * @param {object} data.parties.gt - Object for party predicting "greater than" threshold
 * @param {PublicKey} data.parties.gt.pubKey - public key for this party
 * @param {Address} data.parties.gt.address - (optional instead of pubKey) P2PKH address for this party
 * @param {object} data.parties.lte - Object for party predicting "less than or equal to"
 * @param {PublicKey} data.parties.lte.pubKey - public key for this party
 * @param {Address} data.parties.lte.address - (optional instead of pubKey) P2PKH address for this party
 * 
 * @constructor
 */
var OutputScript = function (data) {
    
    this.oraclePubKey = data.oraclePubKey
    this.threshold = data.threshold
    this.parties = data.parties
}


/**
 * @returns {Script}
 */
OutputScript.prototype.toScript = function () {
    //Output Script
    let outScript = Script()

    outScript.add('OP_DUP')
    outScript.add('OP_4')
    outScript.add('OP_SPLIT')
    outScript.add('OP_SWAP')
    outScript.add('OP_CHECKLOCKTIMEVERIFY')
    outScript.add('OP_DROP')

    const threshBuf = Buffer.alloc(4, 0);
    ScriptNumber.encode(this.threshold).copy(threshBuf);
    outScript.add(threshBuf)

    outScript.add('OP_LESSTHANOREQUAL')
    outScript.add('OP_3')
    outScript.add('OP_PICK')
    outScript.add('OP_HASH160')
    outScript.add('OP_SWAP')

    outScript.add('OP_IF')
    outScript.add(this.buildPartyConditional('lte'))
    outScript.add('OP_ELSE')
    outScript.add(this.buildPartyConditional('gt'))
    outScript.add('OP_ENDIF')

    outScript.add(this.oraclePubKey.toBuffer())

    outScript.add('OP_CHECKDATASIGVERIFY')
    outScript.add('OP_CHECKSIG')

    return outScript
}


/**
 * @returns {Buffer}
 */
OutputScript.prototype.toBuffer = function () {
    let outScript = this.toScript()
    return outScript.toBuffer()
}


/**
 * Return P2SH version of script
 * 
 * @returns {Script}
 */
OutputScript.prototype.toScriptHash = function () {
    let outputBuf = this.toBuffer()
    var outputP2SH = new Script()
    .add('OP_HASH160')
    .add(Hash.sha256ripemd160(outputBuf))
    .add('OP_EQUAL')

    return outputP2SH
}


/**
 * Return P2SH address
 * @param {Network|string=} network - a {@link Network} object, or a string with the network name ('livenet' or 'testnet')
 * 
 * @returns {Address}
 */
OutputScript.prototype.toAddress = function (network) {
    network = network || 'livenet'
    let address = new Address(this.toScriptHash(), network, 'scripthash')
    return address
}


/**
 * @param {string} gtOrLte = "gt" or "lte"
 * 
 * @returns {Script}
 */
OutputScript.prototype.buildPartyConditional = function(gtOrLte) {
    let party = this.parties[gtOrLte]
    if(party.address) {
        if(typeof(party.address) == 'string')
            party.address = Address.fromString(party.address)
        if(party.address instanceof Address)
            party.pubKey = party.address
    }
    if(party.pubKey instanceof PublicKey)
        party.pubKey = party.pubKey.toAddress()
        
    let s = Script()
    .add(party.pubKey.hashBuffer)
    .add('OP_EQUALVERIFY')

    return s
}


/**
 * Parse scriptPubKey into object reflecting inputs
 * @param {string}
 * 
 * @returns {object}
 */
OutputScript.parseScriptPubKey = function(hexString) {
    let getAllIndexes = function (arr, val) {
        var indexes = [], i;
        for(i = 0; i < arr.length; i++)
            if (arr[i] === val)
                indexes.push(i);
        return indexes;
    }

    let raw_script = Buffer.from(hexString, 'hex')
    let script = new Script(raw_script)
    let outscriptArr = script.toASM().split(' ')
    // console.log('outscriptArr', outscriptArr)
    let parsedData = {
        threshold: ScriptNumber.decode(Buffer.from(outscriptArr[6],'hex'), 4, false),
        oraclePubKey: outscriptArr[19],
        parties: {
            gt: {pubKeyHash: outscriptArr[16]},
            lte: {pubKeyHash: outscriptArr[13]}
        }
    }

    return parsedData
}

module.exports = OutputScript