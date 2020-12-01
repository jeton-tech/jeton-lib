const jeton = require('../index')
const PrivateKey = jeton.PrivateKey
const ThresholdMessage = jeton.threshold.Message
const OutputScript = jeton.threshold.OutputScript
const Transaction = jeton.Transaction
const Signature = jeton.Signature

// Create keypairs for 2 players and an oracle
const priv1 = new PrivateKey("KzwmMwHjbmRRdtwVUowKpYmpnJmMaVyGTwYLmh2qmiWcqgd7W9fG")
const pub1 = priv1.toPublicKey()
const priv2 = new PrivateKey("KzyhHmmxwFbv2Mo8bQsJQwXhrCgAtjsCmuqBBmGZrcjfTn1Xvzw1")
const pub2 = priv2.toPublicKey()

var utxoForPub2 = new Transaction.UnspentOutput({ 
    txid:
    'b2b671f0cb3d7710b5d8a8420fff14b18173de876da710438dafa0ae6e8f5357',
    vout: 1,
    satoshis: 10200,
    scriptPubKey: '76a9149383fa6588a176c2592cb2f4008d779293246adb88ac' 
})

var utxoForPub1 = new Transaction.UnspentOutput({ 
    txid:
    'ee874221a431cf09d3373c4b9ffbb1e8fe80526d4304695e2f97541fc084c8f4',
    vout: 1,
    satoshis: 10200,
    scriptPubKey: '76a914b011100d12d0537232692b3c113be5a8f505395588ac' 
})

// Create array of UTXO arrays
var splitUtxos = [utxoForPub1, utxoForPub2]

const oraclePriv = new PrivateKey('L5FDo3MEb2QNs2aQJ5DVGSDE5eBzVsgZny15Ri649RjysWAeLkTs')
const oraclePub = oraclePriv.toPublicKey();
console.log('user 1 pubkey', pub1.toString())
console.log('user 2 pubkey', pub2.toString())
console.log('oracle pubkey', oraclePub.toString())

const blockheight = 660211
const price = 220.2098

// This is the ASM for the redeem script if done in CashScript
// 0556 f2120a 029207e74ee73342f9af30859c03f684da444344d957a949c768316519f9df6a36 02c3e42dd2a3806f1bc9a9f32c3a97b872ed03ce8a779242b8bf2dba636ce655b0 OP_6 OP_PICK OP_4 OP_SPLIT OP_DROP OP_BIN2NUM OP_7 OP_PICK OP_4 OP_SPLIT OP_NIP OP_BIN2NUM OP_OVER OP_5 OP_ROLL OP_GREATERTHANOREQUAL OP_VERIFY OP_SWAP OP_CHECKLOCKTIMEVERIFY OP_DROP OP_3 OP_ROLL OP_GREATERTHANOREQUAL OP_VERIFY OP_3 OP_ROLL OP_4 OP_ROLL OP_3 OP_ROLL OP_CHECKDATASIGVERIFY OP_CHECKSIG

let message = new ThresholdMessage(blockheight, price).message
console.log('message', message)
let oracleSig = Signature.signCDS(message, oraclePriv)
// console.log('sig DER', oracleSig.toDER())
let verify = ThresholdMessage.verifySignature(message, oracleSig, oraclePub)
// console.log('signature verified?', verify)

// Create the output script
var outputScriptData = {
    threshold: 218,
    oraclePubKey: oraclePub,
    parties: {
        gt: {pubKey: pub1},
        lte: {pubKey: pub2}
    }
}

outScript = new OutputScript(outputScriptData)

let outputScript = outScript.toScript()

// console.log(outputScript)

let outScriptHex = outScript.toScript().toHex()

// console.log('destination P2SH', outScript.toAddress())

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
        .sign([priv1, priv2], sighash)     // Signs all the inputs it can
}

// Combine the transactions by merging the inputs
var fundTx = Transaction.mergeTransactionInputs(txArray)

// var itx = new Transaction(fundTx.toString())

// console.log('fundTx', itx.toObject())

// Now spend the escrow transaction...

var escrowUtxo = Transaction.utxoFromTxOutput(fundTx, 0)

// Make Transaction from escrow UTXO
sighash = (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)

var spendTx = new Transaction()
.from(escrowUtxo)
.to(priv1.toAddress(), 19000)
.lockUntilBlockHeight(blockheight) // Must be after the blockheight in the script

//console.log(spendTx.toObject())

// Sign CDS input at index 0 as player 1
spendTx.signThreshold(0, priv1, message, oracleSig, outScript.toScript(), sighash)

console.log(spendTx.toObject())
console.log('estimated size', spendTx._estimateSize())
console.log('verify tx full sig', spendTx.verify())
console.log('jeton signature verified?', spendTx.verifyScriptSig(0))
