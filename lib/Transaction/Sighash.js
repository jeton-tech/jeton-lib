const bitcore = require('bitcore-lib-cash')
const Sighash = bitcore.Transaction.Sighash
const BufferWriter = bitcore.encoding.BufferWriter;
const BufferReader = bitcore.encoding.BufferReader;
const BN = bitcore.crypto.BN;
const Hash = bitcore.crypto.Hash;
const Signature = bitcore.crypto.Signature;
const BufferUtil = bitcore.util.buffer;
const $ = bitcore.util.preconditions;
const _ = bitcore.deps._;

Sighash.getPreimage = function(transaction, inputNumber, subscript) {
    var input = transaction.inputs[inputNumber];
    var satoshisBN = input.output.satoshisBN;
    $.checkArgument(
      satoshisBN instanceof BN, 
      'For ForkId=0 signatures, satoshis or complete input must be provided'
    );

    var sighashType = (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID);
  
    function GetForkId() {
      return 0; // In the UAHF, a fork id of 0 is used (see [4] REQ-6-2 NOTE 4)
    };

    function GetPrevouts(tx) {
        var writer = new BufferWriter()
  
      _.each(tx.inputs, function(input) {
          writer.writeReverse(input.prevTxId);
          writer.writeUInt32LE(input.outputIndex);
      });
  
      var buf = writer.toBuffer();
      return buf
    }
  
    function GetSequences(tx) {
      var writer = new BufferWriter()
  
      _.each(tx.inputs, function(input) {
        writer.writeUInt32LE(input.sequenceNumber);
      });
  
      var buf = writer.toBuffer();
      return buf;
    }
  
    function GetOutputs(tx, n) {
      var writer = new BufferWriter()
  
      if ( _.isUndefined(n)) {
        _.each(tx.outputs, function(output) {
          output.toBufferWriter(writer);
        });
      } else {
        tx.outputs[n].toBufferWriter(writer);
      }
     
      var buf = writer.toBuffer();
      return buf;
    }
  
    var hashPrevouts = BufferUtil.emptyBuffer(32);
    var hashSequences = BufferUtil.emptyBuffer(32);
    var hashOutputs = BufferUtil.emptyBuffer(32);

    var prevouts = GetPrevouts(transaction);
    hashPrevouts = Hash.sha256sha256(prevouts);
    var sequences = GetSequences(transaction);
    hashSequences = Hash.sha256sha256(sequences);
    var outputs = GetOutputs(transaction);
    hashOutputs = Hash.sha256sha256(outputs);
  
    var writer = new BufferWriter()
  
    // Version
    writer.writeInt32LE(transaction.version);
  
    // Input prevouts/nSequence (none/all, depending on flags)
    writer.write(hashPrevouts);
    writer.write(hashSequences);
  
    //  outpoint (32-byte hash + 4-byte little endian)
    writer.writeReverse(input.prevTxId);
    writer.writeUInt32LE(input.outputIndex);
  
    // scriptCode of the input (serialized as scripts inside CTxOuts)
    writer.writeVarintNum(subscript.toBuffer().length)
    writer.write(subscript.toBuffer());
  
    // value of the output spent by this input (8-byte little endian)
    writer.writeUInt64LEBN(satoshisBN);
    
    // nSequence of the input (4-byte little endian) 
    var sequenceNumber = input.sequenceNumber;
    writer.writeUInt32LE(sequenceNumber);
  
    // Outputs (none/one/all, depending on flags)
    writer.write(hashOutputs);
  
    // Locktime
    writer.writeUInt32LE(transaction.nLockTime);
  
    // sighashType 
    writer.writeUInt32LE(sighashType >>>0);

    // console.log('preimage', [
    //     transaction.version,
    //     hashPrevouts.toString('hex'),
    //     hashSequences.toString('hex'),
    //     input.prevTxId.toString('hex'),
    //     input.outputIndex,
    //     subscript.toBuffer().length,
    //     subscript.toBuffer().toString('hex'),
    //     satoshisBN,
    //     sequenceNumber,
    //     hashOutputs.toString('hex'),
    //     transaction.nLockTime,
    //     sighashType >>>0
    //   ])
  
    var buf = writer.toBuffer();
    var buf256 = Hash.sha256(buf);
    var ret = Hash.sha256sha256(buf);
    // ret = new BufferReader(ret).readReverse();

    resObj = {
        prevouts: prevouts,
        prevoutsHash: hashPrevouts,
        sequences: sequences,
        hashSequences: hashSequences,
        preimage: buf,
        // preimage256: buf256,
        // hashPreimage: ret,
    }
    return resObj;
  }

module.exports = Sighash