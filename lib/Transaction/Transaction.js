const bitcore = require('bitcore-lib-cash')
const Transaction = bitcore.Transaction
const Script = bitcore.Script
const Hash = bitcore.crypto.Hash
const Interpreter = bitcore.Script.Interpreter
const BN = bitcore.crypto.BN
const Sighash = require('./Sighash')
const Signature = require('../Signature')
const InputScript = require('../escrow/InputScript')
const ThresholdInputScript = require('../threshold/InputScript')
const CovenantInputScript = require('../covenant/InputScript')


Transaction.P2SHFlags = Interpreter.SCRIPT_VERIFY_P2SH 
    | Interpreter.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
    | Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID
    | Interpreter.SCRIPT_ENABLE_CHECKDATASIG 
    | Interpreter.SCRIPT_VERIFY_STRICTENC 
    | Interpreter.SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE


/**
 * Adds a Pay-to-Script-Hash input to transaction
 *
 * @param {Script} subScript - original Script
 * @param {number} satoshis - output amount
 * 
 * @returns {Transaction}
 */
Transaction.prototype.toP2SH = function (subScript, satoshis) {
    let outputBuf = subScript.toBuffer()
    let outputP2SH = new Script()
        .add('OP_HASH160')
        .add(Hash.sha256ripemd160(outputBuf))
        .add('OP_EQUAL')
    this.addOutput(new Transaction.Output({
        script: outputP2SH,
        satoshis: satoshis
    }))

    return this
}

/**
 * Signs an escrow transaction as defined in jeton.escrow.OutputScript
 *
 * @param {number} inputIndex - index of the input to sign
 * @param {PrivateKey} winnerPrivKey - the private key of the escrow beneficiary
 * @param {string} refMsg - the message for the outcome
 * @param {Signature} refSig - the signature for the message and referee public key
 * @param {Script} subscript - the non-P2SH (original) scriptPubKey
 * @param {number} sighash - the type of signature
 * 
 * @returns {Transaction}
 */
Transaction.prototype.signEscrow = function (inputIndex, winnerPrivKey, refMsg, refSig, subscript, sighash) {
    sighash = sighash || (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)

    let input = this.toObject()['inputs'][inputIndex]
    let p2pkhSig = Sighash.sign(this, winnerPrivKey, sighash, inputIndex, subscript, BN.fromNumber(input.output.satoshis), Transaction.P2SHFlags)

    let winnerScript = Script.buildPublicKeyHashIn(winnerPrivKey.toPublicKey(), p2pkhSig, sighash)

    // Generate scriptSig
    let inputScriptData = {
        refereeSig: refSig,
        message: refMsg,
        winnerScript: winnerScript,
        outputScript: subscript
    }
    
    inScript = new InputScript(inputScriptData)

    // Set scriptSig for inputIndex
    this.inputs[inputIndex].setScript(inScript.toScript())

    return this
}


/**
 * Signs an threshold escrow transaction as defined in jeton.threshold.OutputScript
 *
 * @param {number} inputIndex - index of the input to sign
 * @param {PrivateKey} winnerPrivKey - the private key of the escrow beneficiary
 * @param {string} oracleMsg - the message for the outcome
 * @param {Signature} oracleSig - the signature for the message and referee public key
 * @param {Script} subscript - the non-P2SH (original) scriptPubKey
 * @param {number} sighash - the type of signature
 * 
 * @returns {Transaction}
 */
Transaction.prototype.signThreshold = function (inputIndex, winnerPrivKey, oracleMsg, oracleSig, subscript, sighash) {
    sighash = sighash || (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)

    let input = this.toObject()['inputs'][inputIndex]
    let p2pkhSig = Sighash.sign(this, winnerPrivKey, sighash, inputIndex, subscript, BN.fromNumber(input.output.satoshis), Transaction.P2SHFlags)

    let winnerScript = Script.buildPublicKeyHashIn(winnerPrivKey.toPublicKey(), p2pkhSig, sighash)

    // Generate scriptSig
    let inputScriptData = {
        oracleSig: oracleSig,
        message: oracleMsg,
        winnerScript: winnerScript,
        outputScript: subscript
    }
    
    inScript = new ThresholdInputScript(inputScriptData)

    // Set scriptSig for inputIndex
    this.inputs[inputIndex].setScript(inScript.toScript())

    return this
}

Transaction.prototype.signCovenant = function (inputIndex, winnerPrivKey, refMsg, refSig, subscript, sighash) {
    sighash = sighash || (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)

    let input = this.toObject()['inputs'][inputIndex]
    let p2pkhSig = Sighash.sign(this, winnerPrivKey, sighash, inputIndex, subscript, BN.fromNumber(input.output.satoshis), Transaction.P2SHFlags)

    let winnerScript = Script.buildPublicKeyHashIn(winnerPrivKey.toPublicKey(), p2pkhSig, sighash)

    let preimage = Sighash.getPreimage(this, inputIndex, subscript)

    // Generate scriptSig
    let inputScriptData = {
        refereeSig: refSig,
        message: refMsg,
        winnerScript: winnerScript,
        outputScript: subscript,
        preimage: preimage
    }
    
    inScript = new CovenantInputScript(inputScriptData)

    // Set scriptSig for inputIndex
    this.inputs[inputIndex].setScript(inScript.toScript())

    return this
}


/**
 * Verify that a P2SH input is properly signed
 *
 * @param {number} inputIndex - the index of the input to be verified
 * 
 * @returns {boolean}
 */
Transaction.prototype.verifyScriptSig = function (inputIndex) {
    let input = this.toObject()['inputs'][inputIndex]
    let inScriptHex = input.script
    let inScript = Script.fromHex(inScriptHex)
    let outScriptHex = input.output.script
    let outScript = Script.fromHex(outScriptHex)
    let verified = Interpreter().verify(inScript, outScript, this, inputIndex, Transaction.P2SHFlags, BN.fromNumber(input.output.satoshis))
    return verified
}


/**
 * Merges transactions (must use SIGHASH_ANYONECANPAY)
 *
 * @param {Transaction[]} txArray
 * 
 * @returns {Transaction}
 */
Transaction.mergeTransactionInputs = function (txArray) {
    let baseTx = txArray.shift()
    for(let i = 0; i < txArray.length; i++) {
        let param = {}
        param.prevTxId = txArray[i].inputs[0].prevTxId
        param.outputIndex = txArray[i].inputs[0].outputIndex
        param.sequenceNumber = txArray[i].inputs[0].sequenceNumber
        param.script = txArray[i].inputs[0].script
        let input = new Transaction.Input(param)

        baseTx.addInput(input, param.script, 1000)
    }
    return baseTx
}


/**
 * Format UTXOs for easy use with Transaction.to()
 *
 * @param {object[]} utxoArray
 * 
 * @returns {UnspentOutput[][]}
 */
Transaction.formatUtxos = function (utxoArray) {
    let result = []
    for (let i = 0; i < utxoArray.length; i++) {
        let scriptPubKey = utxoArray[i].scriptPubKey
        let utxos = utxoArray[i].utxos
        utxos = utxos.map(function addScriptPubKey(utxo) {
            utxo.scriptPubKey = scriptPubKey
            return new Transaction.UnspentOutput(utxo)
        })

        result[i] = utxos
    }
    return result
}


/**
 * Get the satoshi total for an array of utxos
 *
 * @param {object[] | UnspentOutput[]} utxos
 * 
 * @returns {number}
 */
Transaction.utxosTotalSatoshis = function (utxos) {
    let totalSats = utxos.reduce(function sumSats(total, utxo) {
        return total + utxo.satoshis
    }, 0)
    return totalSats
}


Transaction.constructSplitTx = function (inputUtxos, destinationAddr, amountToSend, minerFee) {
    totalSats = Transaction.utxosTotalSatoshis(inputUtxos)
    tx = new Transaction()
    for (let i=0; i < inputUtxos.length; i++) {
        tx.from(inputUtxos[i])
    }
    tx.to(destinationAddr, amountToSend)
    tx.to(destinationAddr, totalSats - amountToSend - minerFee)
    return tx
}


/**
 * Generate an UnspentOutput from the output of a transaction
 * @param {Transaction} transaction
 * @param {number} outputIndex
 * 
 * @returns {UnspentOutput}
 */
Transaction.utxoFromTxOutput = function (transaction, outputIndex) {
    txObj = transaction.toObject()
    return new Transaction.UnspentOutput({
        "txId" : txObj.hash,
        "outputIndex" : outputIndex,
        "script" : txObj.outputs[outputIndex].script,
        "satoshis" : txObj.outputs[outputIndex].satoshis
    })
}


module.exports = Transaction