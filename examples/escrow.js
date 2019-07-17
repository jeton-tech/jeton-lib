const jeton = require('../index')
const PrivateKey = jeton.PrivateKey
const Signature = jeton.Signature
const OutputScript = jeton.escrow.OutputScript
const Transaction = jeton.Transaction

// Create keypairs for 3 players and a referee
const priv1 = new PrivateKey("L1wChPjacPamAFVbUsZZi5cEd3kMysZSgfDGprGEj91wTP6sh7KH")
const pub1 = priv1.toPublicKey()
const priv2 = new PrivateKey("KzyhHmmxwFbv2Mo8bQsJQwXhrCgAtjsCmuqBBmGZrcjfTn1Xvzw1")
const pub2 = priv2.toPublicKey()
const priv3 = new PrivateKey("KzwmMwHjbmRRdtwVUowKpYmpnJmMaVyGTwYLmh2qmiWcqgd7W9fG")
const pub3 = priv3.toPublicKey()

var refPriv = new PrivateKey('L5FDo3MEb2QNs2aQJ5DVGSDE5eBzVsgZny15Ri649RjysWAeLkTs')
var refpk = refPriv.toPublicKey();

// Create example UTXOs for players 2 and 3 which will be used to fund the escrow
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

// Create array of UTXOs
var splitUtxos = [utxoForPub2, utxoForPub3]

// Create the output script
var outputScriptData = {
    refereePubKey: refpk,
    parties: [
        {message: 'player1wins', pubKey: pub1.toAddress()},
        {message: 'player2wins', pubKey: pub2.toAddress()},
        {message: 'player3wins', pubKey: pub3.toAddress()}
    ]
}

outScript = new OutputScript(outputScriptData)

// Set miner fee and total amount to send (will be split between UTXOs array)
var splitUtxoMinerFee = 200
var amountToSend = 20000

var splitTxSendAmount = (amountToSend / splitUtxos.length)

// Create two separate SIGHASH_ANYONECANPAY transactions from players 2 and 3 to fund the escrow
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

// Now spend the escrow UTXO from the newly created transaction...
var escrowUtxo = Transaction.utxoFromTxOutput(fundTx, 0)

// Make Transaction from escrow UTXO
sighash = (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)

var spendTx = new Transaction()
.from(escrowUtxo)
.to(priv1.toAddress(), 19000)

// Sign message with referee private key for player 1 wins
var refereeSig = Signature.signCDS(outputScriptData.parties[0].message, refPriv)

// Sign CDS input at index 0 as player 1
spendTx.signEscrow(0, priv1, outputScriptData.parties[0].message, refereeSig, outScript.toScript(), sighash)

console.log(spendTx.toObject())
console.log('estimated size', spendTx._estimateSize())
console.log('verify tx full sig', spendTx.verify())
console.log('jeton signature verified?', spendTx.verifyScriptSig(0))