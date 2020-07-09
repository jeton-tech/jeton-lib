const bitcore = require('bitcore-lib-cash')
const Address = bitcore.Address
const Hash = bitcore.crypto.Hash
const Script = bitcore.Script
const PublicKey = bitcore.PublicKey
const Output = bitcore.Transaction.Output
const ScriptNumber = require('../threshold/ScriptNumber')

const gcd = function (input) {
    if (toString.call(input) !== "[object Array]")  
            return  false;  
    var len, a, b;
        len = input.length;
        if ( !len ) {
            return null;
        }
        a = input[ 0 ];
        for ( var i = 1; i < len; i++ ) {
            b = input[ i ];
            a = gcd_two_numbers( a, b );
        }
        return a;
};
  
const gcd_two_numbers = function(x, y) {
    if ((typeof x !== 'number') || (typeof y !== 'number')) 
        return false;
    x = Math.abs(x);
    y = Math.abs(y);
    while(y) {
        var t = y;
        y = x % y;
        x = t;
    }
    return x;
};


/**
 * Instantiate an object to create covenant scriptPubKey
 *
 * @param {object} data - The encoded data in various formats
 * @param {PublicKey[]} data.pubKeys - (optional) The public keys for required signatures
 * @param {Output[] | object[]} data.outputs - array of party objects
 * @param {int[]} data.prorata - array of integers corresponding to the proportional representation of data.output values
 * 
 * @constructor
 */
var OutputScript = function (data) {
    this.pubKeys = data.pubKeys ? data.pubKeys : []

    if (data.outputs) {
        try {
            this.outputs = data.outputs.map(function (out) {
                if (!(out instanceof Output)) {
                    out = new Output(out)
                }
                return out
            })
        } catch(err) {
            throw new Error ('Invalid format for outputs')
        }
    }

    this.prorata = !Array.isArray(data.prorata) ? null : data.prorata.map(x => x / gcd(data.prorata))
}


/**
 * @returns {Script}
 */
OutputScript.prototype.toScript = function () {
    //Output Script
    let outScript = new Script()
    // MultiSig
    .add(this.buildMultiSigOut(this.pubKeys))

    .add('OP_2DUP')
    .add('OP_CHECKSIGVERIFY')
    .add('OP_SWAP')
    .add('OP_SIZE')
    .add('OP_1SUB')
    .add('OP_SPLIT')
    .add('OP_DROP')
    .add('OP_SWAP')
    .add('OP_ROT')
    // Get outputs
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
    .add('OP_DUP')

    // Begin output checks
    for (let i = 0; i < this.outputs.length; i++) {
        let output = this.outputs[i]
        let fullOutBuf = output.toBufferWriter().toBuffer()
        // Proportional
        if (this.prorata && this.prorata.length > 0) {
            if (this.prorata.length < 2) {
                throw new Error ('Prorportional convenants must have at least 2 amounts in prorata array')
            }
            if (this.prorata.length != this.outputs.length) {
                throw new Error ('Proportional covenants must have a prorata value for every specified output')
            }
            outScript.add(this.buildProrataCheck(i))
            let outScriptBuf = fullOutBuf.slice(8)
            outScript.add(outScriptBuf)
        }
        else {
            // Exact amount
            outScript.add(fullOutBuf)
        }
        outScript.add(this.buildOutputCheck(output))
    }

    outScript.add('OP_DROP')
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
OutputScript.prototype.buildProrataCheck = function(index) {
    let value = ScriptNumber.encode(this.prorata[index])
    // Enforce minimum encoding
    if (this.prorata[index] <= 16) {
        if (this.prorata[index] <= 0) {
            throw new Error ('Invalid value in prorata array at index ' + index)
        }
        value = 'OP_' + this.prorata[index]
    }

    let s = new Script()
    .add('OP_8')
    .add('OP_SPLIT')
    .add('OP_SWAP')
    .add('OP_BIN2NUM')
    .add('OP_DUP')
    .add(value)
    .add('OP_BIN2NUM')
    .add('OP_MOD')
    .add('OP_0')
    .add('OP_EQUALVERIFY')
    .add(value)
    .add('OP_BIN2NUM')
    .add('OP_DIV')
    // Logic for inputs after the first
    if (index > 0) {
        s.add('OP_DUP')
        .add('OP_FROMALTSTACK')
        .add('OP_EQUALVERIFY')
    }
    s.add('OP_TOALTSTACK')

    return s
}

/**
 * @returns {Script}
 */
OutputScript.prototype.buildOutputCheck = function(output) {
    let s = new Script()
    .add('OP_SIZE')
    .add('OP_ROT')
    .add('OP_SWAP')
    .add('OP_SPLIT')
    .add('OP_SWAP')
    .add('OP_ROT')
    .add('OP_EQUALVERIFY')

    return s
}

/**
 * @returns {Script}
 */
OutputScript.prototype.buildMultiSigOut = function(pubKeys) {
    let s = new Script()
    for (i = 0; i < pubKeys.length; i++) {
        s.add(pubKeys[i].toBuffer())
        if (pubKeys.length > i + 1) {
            s.add('OP_CHECKSIGVERIFY')
        }
    }

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