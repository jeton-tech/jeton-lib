# Jeton Lib

**Extension of bitcore-lib-cash for advanced Bitcoin Cash transaction types**

## Purpose

Bitcoin Cash has script functionality, such as OP_CHECKDATASIG which is unique among Bitcoin forks. This functionality allows Bitcoin Cash users to particpate in on-chain, non-custodial escrow transactions (and more). Jeton Lib extends the popular [bitcore-cash-lib](https://github.com/bitpay/bitcore/tree/master/packages/bitcore-lib-cash) library to allow for easy creation of transactions which leverage the powerful capabilities of Bitcoin Cash.

## Examples

Complete examples are located in the [/examples](https://github.com/jeton-tech/jeton-lib/tree/master/examples) directory.

### Include jeton-lib wherever you use bitcore-lib-cash

```javascript
const jeton = require('jeton-lib')
const PrivateKey = jeton.PrivateKey
const Signature = jeton.Signature
const OutputScript = jeton.escrow.OutputScript
const Transaction = jeton.Transaction
```

### Generate an escrow scriptPubKey

```javascript
// Create keypairs for 3 players and a referee
var priv1 = new PrivateKey("L1wChPjacPamAFVbUsZZi5cEd3kMysZSgfDGprGEj91wTP6sh7KH")
var pub1 = priv1.toPublicKey()
var priv2 = new PrivateKey("KzyhHmmxwFbv2Mo8bQsJQwXhrCgAtjsCmuqBBmGZrcjfTn1Xvzw1")
var pub2 = priv2.toPublicKey()
var priv3 = new PrivateKey("KzwmMwHjbmRRdtwVUowKpYmpnJmMaVyGTwYLmh2qmiWcqgd7W9fG")
var pub3 = priv3.toPublicKey()

var refPriv = new PrivateKey('L5FDo3MEb2QNs2aQJ5DVGSDE5eBzVsgZny15Ri649RjysWAeLkTs')
var refpk = refPriv.toPublicKey();

// Create the output script
var outputScriptData = {
    refereePubKey: refpk,
    parties: [
        {message: 'player1wins', pubKey: pub1},
        {message: 'player2wins', pubKey: pub2},
        {message: 'player3wins', pubKey: pub3}
    ]
}

outScript = new OutputScript(outputScriptData)
assert(outScript.toScript().toASM() === 'OP_DUP 706c617965723177696e73 OP_EQUAL OP_IF OP_DROP 706c617965723177696e73 02d180cd5d509cf23fd2139ea53634bac12d29d0a71d22ad97a59a9379faa3250a OP_CHECKDATASIGVERIFY OP_DUP OP_HASH160 44a45625a1fda976376e7d59d27fc621f9c9d382 OP_ELSE OP_DUP 706c617965723277696e73 OP_EQUAL OP_IF OP_DROP 706c617965723277696e73 02d180cd5d509cf23fd2139ea53634bac12d29d0a71d22ad97a59a9379faa3250a OP_CHECKDATASIGVERIFY OP_DUP OP_HASH160 9383fa6588a176c2592cb2f4008d779293246adb OP_ELSE OP_DUP 706c617965723377696e73 OP_EQUAL OP_IF OP_DROP 706c617965723377696e73 02d180cd5d509cf23fd2139ea53634bac12d29d0a71d22ad97a59a9379faa3250a OP_CHECKDATASIGVERIFY OP_DUP OP_HASH160 b011100d12d0537232692b3c113be5a8f5053955 OP_ENDIF OP_ENDIF OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG')
```

### Create a transaction with a P2SH output from escrow script

```javascript
var utxo = new Transaction.UnspentOutput({ 
    txid:
    'ee874221a431cf09d3373c4b9ffbb1e8fe80526d4304695e2f97541fc084c8f4',
    vout: 1,
    satoshis: 10200,
    scriptPubKey: '76a914b011100d12d0537232692b3c113be5a8f505395588ac' 
})

var fundEscrowTx = new Transaction()
        .from(utxo)          // Feed information about what unspent outputs one can use
        .toP2SH(outScript, 10000)
        .sign([priv2])     // Signs all the inputs it can
```

### Spend escrow UTXO

```javascript
var escrowUtxo = Transaction.utxoFromTxOutput(fundEscrowTx, 0)

// Make Transaction from escrow UTXO
sighash = (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)

var spendEscrowTx = new Transaction()
.from(escrowUtxo)
.to(priv1.toAddress(), 9000)

// Sign message with referee private key for player 1 wins
var refereeSig = Signature.signCDS(outputScriptData.parties[0].message, refPriv)

// Sign CDS input at index 0 as player 1
spendEscrowTx.signEscrow(0, priv1, outputScriptData.parties[0].message, refereeSig, outScript.toScript(), sighash)
```

## License

Code released under [the MIT license](https://github.com/jeton-tech/jeton-lib/blob/master/LICENSE).
