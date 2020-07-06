const bitcore = require('bitcore-lib-cash')
const Address = bitcore.Address
const Hash = bitcore.crypto.Hash
const Script = bitcore.Script
const PublicKey = bitcore.PublicKey
const ScriptNumber = require('../threshold/ScriptNumber')


/**
 * Instantiate an object to create covenant scriptPubKey
 *
 * @param {object} data - The encoded data in various formats
 * @param {PublicKey} data.refereePubKey
 * @param {object[]} data.parties - array of party objects
 * @param {string} data.parties[].message - message for this party
 * @param {PublicKey} data.parties[].pubKey - public key for this party
 * @param {Address} data.parties[].address - (optional instead of pubKey) P2PKH address for this party
 * 
 * @constructor
 */
var OutputScript = function (data) {
    
    this.refereePubKey = data.refereePubKey
    this.parties = data.parties
}


/**
 * @returns {Script}
 */
OutputScript.prototype.toScript = function () {
    //Output Script
    let outScript = Script()

    // // Build the conditionals for the parties
    // for(let i = 0; i < this.parties.length; i++) {
    //     outScript.add(this.buildPartyConditional(i))
    //     if(i < (this.parties.length - 1) ) {
    //         outScript.add('OP_ELSE')
    //     }
    // }
    // // End the conditionals
    // for(let i = 0; i < this.parties.length; i++) {
    //     outScript.add('OP_ENDIF')
    // }
    const party = this.parties[0]
    if(party.address) {
        if(typeof(party.address) == 'string')
            party.address = Address.fromString(party.address)
        if(party.address instanceof Address)
            party.pubKey = party.address
    }
    if(party.pubKey instanceof PublicKey)
        party.pubKey = party.pubKey.toAddress()

    outScript.add('OP_DUP')
    .add('OP_HASH160')
    .add(party.pubKey.hashBuffer)
    .add('OP_EQUALVERIFY')
    .add('OP_2DUP')
    .add('OP_CHECKSIGVERIFY')
    .add('OP_SWAP')
    .add('OP_SIZE')
    .add('OP_1SUB')
    .add('OP_SPLIT')
    .add('OP_DROP')
    .add('OP_SWAP')
    .add('OP_ROT')
    // Outputs
    .add('OP_DUP')
    .add('OP_SIZE')
    .add(ScriptNumber.encode(40))
    .add('OP_SUB')
    .add('OP_SPLIT')
    .add('OP_NIP')
    .add(ScriptNumber.encode(32))
    .add('OP_SPLIT')
    .add('OP_DROP')
    .add('OP_4')
    .add('OP_ROLL')
    .add('OP_HASH256')
    .add('OP_EQUALVERIFY') // End Outputs

    .add('OP_SHA256')
    .add('OP_SWAP')
    .add('OP_CHECKDATASIG')

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
 * @returns {Script}
 */
OutputScript.prototype.buildPartyConditional = function(index) {
    let party = this.parties[index]
    if(party.address) {
        if(typeof(party.address) == 'string')
            party.address = Address.fromString(party.address)
        if(party.address instanceof Address)
            party.pubKey = party.address
    }
    if(party.pubKey instanceof PublicKey)
        party.pubKey = party.pubKey.toAddress()
        
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
        .add(party.pubKey.hashBuffer)

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

    let parsedData = {
        refereePubKey: null,
        parties: []
    }
    let raw_script = Buffer.from(hexString, 'hex')
    let script = new Script(raw_script)
    let outscriptArr = script.toASM().split(' ')
    let endifAppearances = getAllIndexes(outscriptArr, 'OP_IF')
    // console.log('endifAppearances', endifAppearances)
    for(let i = 0; i < endifAppearances.length; i++) {
        let ifIndex = endifAppearances[i]
        let partyArray = outscriptArr.slice(ifIndex+2, ifIndex+8)
        parsedData.parties[i] = {
            message: Buffer.from(partyArray[0], 'hex').toString(),
            pubKeyHash: partyArray[5]
        }
        parsedData.refereePubKey = partyArray[1]
    }
    return parsedData
}

module.exports = OutputScript