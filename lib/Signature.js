const bitcore = require('bitcore-lib-cash')
const ECDSA = bitcore.crypto.ECDSA
const Hash = bitcore.crypto.Hash
const Signature = bitcore.crypto.Signature


/**
 * Generate a signature compatible with OP_CHECKDATASIG
 *
 * @param {string} message
 * @param {PrivateKey} privateKey
 * 
 * @returns {Signature}
 */
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


/**
 * @returns {Signature}
 */
Signature.cleanSignature = function (sig) {
    let sigHex = sig.toString()
    return Signature.fromString(sigHex)
}

/**
 * Verifies a given signature
 *
 * @param {string} message
 * @param {PublicKey} pubKey
 * @param {Signature} signature
 * 
 * @returns {object}
 */
Signature.verify = function (message, pubKey, signature) {
    let hash = Hash.sha256(Buffer.from(message))
    let ecdsa = ECDSA().set({
        hashbuf: hash,
        // endian: endian,
        sig: signature,
        pubkey: pubKey
    })
    let verify = ecdsa.verify()
    return verify.verified
}


module.exports = Signature