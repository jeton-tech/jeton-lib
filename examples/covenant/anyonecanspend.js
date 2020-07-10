const jeton = require('../../index')
const PrivateKey = jeton.PrivateKey
const Signature = jeton.Signature
const Script = jeton.Script
const OutputScript = jeton.covenant.OutputScript
const Transaction = jeton.Transaction
const Sighash = Transaction.Sighash
const Output = Transaction.Output

// Create keypairs for 3 players and a referee
const priv1 = new PrivateKey("L1wChPjacPamAFVbUsZZi5cEd3kMysZSgfDGprGEj91wTP6sh7KH")
const pub1 = priv1.toPublicKey()
const priv2 = new PrivateKey("KzyhHmmxwFbv2Mo8bQsJQwXhrCgAtjsCmuqBBmGZrcjfTn1Xvzw1")
const pub2 = priv2.toPublicKey()
const priv3 = new PrivateKey("KzwmMwHjbmRRdtwVUowKpYmpnJmMaVyGTwYLmh2qmiWcqgd7W9fG")
const pub3 = priv3.toPublicKey()

var refPriv = new PrivateKey('L5FDo3MEb2QNs2aQJ5DVGSDE5eBzVsgZny15Ri649RjysWAeLkTs')
var refpk = refPriv.toPublicKey();

var utxoForPub2 = new Transaction.UnspentOutput({ 
    txid:
    'b2b671f0cb3d7710b5d8a8420fff14b18173de876da710438dafa0ae6e8f5357',
    vout: 1,
    satoshis: 10200,
    scriptPubKey: '76a9149383fa6588a176c2592cb2f4008d779293246adb88ac' 
})

var utxoForPub3 = new Transaction.UnspentOutput({ 
    txid:
    'ee874221a431cf09d3373c4b9ffbb1e8fe80526d4304695e2f97541fc084c8f4',
    vout: 1,
    satoshis: 10200,
    scriptPubKey: '76a914b011100d12d0537232692b3c113be5a8f505395588ac' 
})


// Create array of UTXO arrays
var splitUtxos = [utxoForPub2, utxoForPub3]

// Create the final covenant destination outputs
var output1 = new Output ({
    script: Script.fromAddress(priv1.toAddress()),
    satoshis: 10010
})
var output2 = new Output ({
    script: Script.fromAddress(priv2.toAddress()),
    satoshis: 3003
})
var output3 = new Output ({
    script: Script.fromAddress(priv3.toAddress()),
    satoshis: 4004
})

// Create the output script
var outputScriptData = {
    outputs: [output1, output2, output3],
}

outScript = new OutputScript(outputScriptData)

var outScriptHex = outScript.toScript().toBuffer().toString('hex')
var parsedScript = OutputScript.parseScriptPubKey(outScriptHex)
var outScript2 = new OutputScript(parsedScript)
var areEqual = outScript.toAddress().toString() == outScript2.toAddress().toString()

// Set miner fee and total amount to send (will be split between UTXOs from useUTXOs array)
var splitUtxoMinerFee = 200
var amountToSend = 20000

var splitTxSendAmount = (amountToSend / splitUtxos.length)

// Create two separate transactions from players 2 and 3 to fund the escrow
var sighash = (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID | Signature.SIGHASH_ANYONECANPAY)
var txArray = []
for (let i = 0; i < splitUtxos.length; i++) {
    txArray[i] = new Transaction()
        .from(splitUtxos[i])          // Feed information about what unspent outputs one can use
        .toP2SH(outScript, amountToSend)
        .sign([priv2, priv3], sighash)     // Signs all the inputs it can
}

// Combine the transactions by merging the inputs
var fundTx = Transaction.mergeTransactionInputs(txArray)
var itx = new Transaction(fundTx.toString())

// Now spend the escrow transaction...
sighash = (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID )

var escrowUtxo = Transaction.utxoFromTxOutput(fundTx, 0)

// Make Transaction from escrow UTXO
var spendTx = new Transaction()
.from(escrowUtxo)
.addOutput(output1)
.addOutput(output2)
.addOutput(output3)

var spendTxBuf = spendTx.toBuffer()

// Sign covenant input at index 0 as party 1
spendTx.signCovenant(0, [priv1], outScript.toScript(), sighash, true) // note the "true" boolean as final argument

console.log(spendTx.toObject())
console.log('OutputScript parsing correctly?', areEqual)
console.log('scriptSig size', Buffer.from(spendTx.toObject().inputs[0].script, 'hex').byteLength)
console.log('estimated size', spendTx._estimateSize())
console.log('verify tx full sig', spendTx.verify())
console.log('jeton signature verified?', spendTx.verifyScriptSig(0))