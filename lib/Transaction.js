const bitcore = require('bitcore-lib-cash')
const Transaction = bitcore.Transaction
const Script = bitcore.Script
const Hash = bitcore.crypto.Hash
const Interpreter = bitcore.Script.Interpreter
const Sighash = Transaction.Sighash
const BN = bitcore.crypto.BN
const Signature = require('./Signature')
const InputScript = require('./escrow/InputScript')


Transaction.P2SHFlags = Interpreter.SCRIPT_VERIFY_P2SH 
    | Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID
    | Interpreter.SCRIPT_ENABLE_CHECKDATASIG 
    | Interpreter.SCRIPT_VERIFY_STRICTENC 
    | Interpreter.SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE


Transaction.prototype.toP2SH = function (scriptPubKey, satoshis) {
    let outputBuf = scriptPubKey.toBuffer()
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


Transaction.prototype.signEscrow = function (inputIndex, winnerPrivKey, refMsg, refSig, subscript, sighash) {
    sighash = sighash || (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)

    let input = this.toObject()['inputs'][inputIndex]
    let p2pkhSig = Sighash.sign(this, winnerPrivKey, sighash, inputIndex, subscript, BN.fromNumber(input.output.satoshis), Transaction.P2SHFlags)

    let winnerScript = Script.buildPublicKeyHashIn(winnerPrivKey.toPublicKey(), p2pkhSig, sighash)

    //console.log('winnerScript', winnerScript)

    let inputScriptData = {
        refereeSig: refSig,
        message: refMsg,
        winnerScript: winnerScript,
        outputScript: subscript
    }
    
    inScript = new InputScript(inputScriptData)
    // Create new input with full signature
    let param = input
    param.script = inScript.toScript()
    newInput = new Transaction.Input(param)
    
    this.removeInput(inputIndex)
    this.addInput(newInput, input.output.script, input.output.satoshis)

    return this
}


Transaction.prototype.verifyScriptSig = function (inputIndex) {
    let input = this.toObject()['inputs'][inputIndex]
    console.log(input.output)
    let inScriptHex = input.script
    let inScript = Script.fromHex(inScriptHex)
    let outScriptHex = input.output.script
    let outScript = Script.fromHex(outScriptHex)
    let verified = Interpreter().verify(inScript, outScript, this, inputIndex, Transaction.P2SHFlags, BN.fromNumber(input.output.satoshis))
    return verified
}


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


Transaction.formatUtxos = function (utxoArray) {
    let result = []
    for (let i = 0; i < utxoArray.length; i++) {
        let scriptPubKey = utxoArray[i].scriptPubKey
        let utxos = utxoArray[i].utxos
        utxos = utxos.map(function addScriptPubKey(utxo) {
            utxo.scriptPubKey = scriptPubKey
            console.log(utxo)
            return new Transaction.UnspentOutput(utxo)
        })

        result[i] = utxos
    }
    return result
}


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