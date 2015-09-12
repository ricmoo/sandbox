/**
 *  Stealth Address Idea
 *
 *  Questions
 *    - Is EC multiply or addition better for non-revocable?
 *    - Should we hash256 the shared secret for any good reason?
 *
 *  Further Discussion
 *    To create addresses that are SPV-friendly, this is my high-level idea. Use the
 *    sha256(targetPublicKey)[0:4] as the tweak, and build data that will match
 *    targetAddress. Then payments should use 1-of-2 multisig:
 *
 *        OP_1 <stealthAddress pubkey> <data to match targetAddress pubkey> OP_2 OP_CHECKMULTISIG
 *
 *    Would this work?
 */

// Libraries
var bigi = require('bigi');
var bitcoinLib = require('bitcoinjs-lib');
var bs58check = require('bs58check')
var ECC = new require('elliptic').ec('secp256k1');

// Convert a public key's hex encoding into an address
function addressFromPublicKeyHex(publicKeyHex) {
    hashed = bitcoinLib.crypto.hash160(new Buffer(publicKeyHex, 'hex'));
    var payload = Buffer.concat([new Buffer([0]), new Buffer(hashed)])
    return bs58check.encode(new Buffer(payload))
}

// Just playing for now... Chose 5 as the start character since 1 is bitcoin, 3 is script...
function stealthAddressFromPublicKeyHex(publicKeyHex) {
    return bs58check.encode(Buffer.concat([
        new Buffer([28]),
        new Buffer(publicKeyHex, 'hex'),
    ]))
}

function publicKeyHexFromStealthAddress(stealthAddress) {
    var decoded = bs58check.decode(stealthAddress);
    if (decoded[0] !== 28 || decoded.length != 34) {
        throw new Error('Invalid stealth address');
    }
    return decoded.slice(1).toString('hex');
}

/**
 *  Generates an address that targetPublicKey can receive funds.
 *
 *  targetPublicKeyHex     - The target address' public key to receive the funds
 *  inputUtxoPrivateKeyHex - A private key of any UTXO included in the transaction
 *  revocable              - If true, the sender can also spend the funds
 */
function generateAddress(targetPublicKeyHex, inputUtxoPrivateKeyHex, revocable) {

    // Convert the he keys into objects
    targetPublicKey = ECC.keyFromPublic(targetPublicKeyHex, 'hex').getPublic();
    inputUtxoPrivateKey = ECC.keyFromPrivate(inputUtxoPrivateKeyHex);

    // Use Diffie-Hellman to derive a shared secret
    var sharedSecret = inputUtxoPrivateKey.derive(targetPublicKey);
    var sharedPrivateKey = ECC.keyFromPrivate(sharedSecret.toArray());

    // Revocable addresses just use the shared secret as the private key
    if (revocable) {
        return {
            address: addressFromPublicKeyHex(sharedPrivateKey.getPublic(true, 'hex')),
            privateKey: sharedSecret.toString('hex')
        }
    }

    // Compute the ECC addition of our sharedSecret's public point and the
    // targetPublicKey's point
    var targetPublicPoint = sharedPrivateKey.getPublic().add(targetPublicKey);

    return {
        address: addressFromPublicKeyHex(targetPublicPoint.encode('hex', true))
    }

}

/**
 *  Generates a full transaction, stealth-ily.
 *
 *  targetPublicKeyHex - The target address' public key to receive the funds
 *  inputUtxos         - The input UTXO set to spend
 *  targetValue        - How much to send
 *  changeAddress      - Where to send the leftover change
 *  transactionFee     - How much to give to the miners
 *  revocable          - If true, the sender can also spend the funds
 *  spvable            - @TODO: see notes at the top for discussion
 */
function generatePayment(targetPublicKeyHex, inputUtxos, targetValue, changeAddress, transactionFee, revocable, spvable) {
    var transaction = new bitcoinLib.TransactionBuilder();

    // Get a stealth address; would ideally pick a random UTXO, for deterministic
    // makes testing easier
    var stealthAddress = generateAddress(targetPublicKeyHex, inputUtxos[0].privateKey, revocable);

    // Add all the UTXO's and tally up the total
    var totalValue = 0;
    for (var i = 0; i < inputUtxos.length; i++) {
        var inputUtxo = inputUtxos[i];
        totalValue += inputUtxo.value;
        transaction.addInput(inputUtxo.txid, inputUtxo.index);
    }

    // Send funds to teh stealth address
    transaction.addOutput(stealthAddress.address, targetValue);

    // Send the change back to ourselves
    var change = totalValue - targetValue - transactionFee;
    if (change) {
        transaction.addOutput(changeAddress, change);
    }

    // Sign the transaction
    for (var i = 0; i < inputUtxos.length; i++) {
        var inputUtxo = inputUtxos[i];
        transaction.sign(i, new bitcoinLib.ECKey(bigi.fromHex(inputUtxo.privateKey), true))
    }

    return transaction.build();
}


/**
 *  If a transaction contains a stealth payment, return it.
 *
 *  targetPrivateKeyHex - The private key for our targetPublicKey's address
 *  txHex               - The hex encoded transaction
 */
function redeemPayment(targetPrivateKeyHex, txHex) {

    // Convert the key into an object
    targetPrivateKey = ECC.keyFromPrivate(targetPrivateKeyHex);

    // Get the transaction all parsed and whatnot
    var transaction = bitcoinLib.Transaction.fromHex(txHex);

    var txidReversed = transaction.getHash().toString('hex');
    var txid = '';
    for (var i = txidReversed.length - 2; i >= 0; i -= 2) {
        txid += txidReversed.substring(i, i + 2);
    }

    // Maps each output address to the output and the output's index
    var addressToOutput = {};
    var addressToOutputIndex = {};

    for (var i = 0; i < transaction.outs.length; i++) {
        var output = transaction.outs[i];
        var address = bitcoinLib.Address.fromOutputScript(output.script).toBase58Check();
        addressToOutput[address] = output;
        addressToOutputIndex[address] = i;
    }

    // Search through the inputs...
    for (var i = 0; i < transaction.ins.length; i++) {
        var input = transaction.ins[i];

        // For now we only support pubkeyhash
        var publicKey = null;
        if (bitcoinLib.scripts.classifyInput(input.script) === 'pubkeyhash') {
            publicKey = input.script.chunks[1];
        } else {
            throw new Error('Needs to handle this...');
        }

        // Get the input's public key
        senderPublicKey = ECC.keyFromPublic(publicKey).getPublic();

        // Use Diffie-Hellman to derive a shared secret
        var sharedSecret = targetPrivateKey.derive(senderPublicKey);
        var sharedPrivateKey = ECC.keyFromPrivate(sharedSecret.toArray());

        // Is the address the revocable address for this public key?
        var address = addressFromPublicKeyHex(sharedPrivateKey.getPublic(true, 'hex'));
        var output = addressToOutput[address];
        if (output) {
            return {
                index: addressToOutputIndex[address],
                value: output.value,
                txid: txid,
                privateKey: sharedSecret.toString(16),
            }
        }

        // Is this address the irrevocable address for this public key?
        //   - That is the ECC addition of the public point from out shared
        //     secret and our known public key
        //   - If so, we can ECC add the shared secret exponent and out private
        //     key for the known public key
        var targetPublicPoint = sharedPrivateKey.getPublic().add(targetPrivateKey.getPublic());
        var address = addressFromPublicKeyHex(targetPublicPoint.encode('hex', true))
        var output = addressToOutput[address];
        if (output) {
            return {
                index: addressToOutputIndex[address],
                value: output.value,
                txid: txid,
                privateKey: bigi.fromHex(sharedSecret.toString(16)).add(bigi.fromHex(targetPrivateKeyHex)).toString(16),
            }
        }
    }
}

module.exports = {
    generateAddress: generateAddress,
    generatePayment: generatePayment,
    redeemPayment: redeemPayment,

    stealthAddressFromPublicKey: stealthAddressFromPublicKeyHex,
    publicKeyFromStealthAddress: publicKeyHexFromStealthAddress,
}

