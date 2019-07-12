const bitcore = require('bitcore-lib-cash')
const ECDSA = bitcore.crypto.ECDSA
const Hash = bitcore.crypto.Hash
const Signature = bitcore.crypto.Signature


Signature.signCDS = function (message, privateKey) {
    let hash = Hash.sha256(Buffer.from(message))
    let ecdsa = new ECDSA()
    ecdsa.hashbuf = hash
    ecdsa.privkey = privateKey
    ecdsa.pubkey = privateKey.toPublicKey()
    ecdsa.signRandomK()
    ecdsa.calci()
    return Signature.cleanSignature(ecdsa.sig);
}


Signature.cleanSignature = function (sig) {
    let sigHex = sig.toString()
    return Signature.fromString(sigHex)
}


module.exports = Signature