# Jeton Lib

**Extension of bitcore-lib-cash for advanced Bitcoin Cash transaction types**

## Examples

Contained in this directory are complete examples for funding and spending of the transaction types made possible by jeton-lib.

[escrow.js](https://github.com/jeton-tech/jeton-lib/tree/master/examples/escrow.js) - Multi-Party escrow where an oracle provides a signature for a given message based on the outcome of an event

[threshold.js](https://github.com/jeton-tech/jeton-lib/tree/master/examples/threshold.js) - Multi-Party escrow where an oracle provides a signature for a message containing blockheight and a value (such as price). The party who is either "greater than" or "less than or equal to" the value in the message can collect after the given blockheight

[covenant/multisig.js](https://github.com/jeton-tech/jeton-lib/tree/master/examples/covenant/multisig.js) - A covenant escrow requiring multiple signatures in which specific amounts must be paid to specific addresses

[covenant/anyonecanpay.js](https://github.com/jeton-tech/jeton-lib/tree/master/examples/covenant/anyonecanpay.js) - A covenant escrow in which specific amounts must be paid to specific addresses and any private key holder can sign

[covenant/proportional.js](https://github.com/jeton-tech/jeton-lib/tree/master/examples/covenant/proportional.js) - A covenant escrow in which amounts must be paid to specific addresses in a prescribed proportion (prorata) and any private key holder can sign

## License

Code released under [the MIT license](https://github.com/jeton-tech/jeton-lib/blob/master/LICENSE).
