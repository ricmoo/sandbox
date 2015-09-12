/**
 *  Test for stealth.js
 *
 */

// The library
var stealth = require('./lib/stealth.js');

// This tests a transaction to find stealth payments and shows them
function testRedeem(txHex) {

    // What the receiver knows
    var targetPrivateKey = "0dd1c15efff522fb2144b317993ed2ece540368172c84fa116725bf6b6a50975";

    // Check!
    return stealth.redeemPayment(targetPrivateKey, txHex);
}

{
    // What the sender knows
    var targetPublicKey = "029ed06e396761c24416cf7323ed4f1cb29763ee9e2b0fccae347d6a2a3eaecbf5";

    console.log(stealth.stealthAddressFromPublicKey(targetPublicKey));
    console.log(stealth.publicKeyFromStealthAddress(stealth.stealthAddressFromPublicKey(targetPublicKey)));

    var myUtxos = [
        {
            index: 0,
            txid: "3cc8b9f5f0882377cf378fec325889f35dc27e14b822126daceabf47f61e7ddb",
            privateKey: "77a8535d57fddfab8470f712ddcbc598c6f481689d91d56b1d90271404aaad2c",
            value: 21000
        },
        {
            index: 0,
            txid: "ef807351a222f866d913126fc2f91f026dcfb2aa341f314020a6337db8f720c6",
            privateKey: "bdf4186692f333f813e8eb828d7b5b0239c94e9dde6ce96fd343f968cb4924e7",
            value: 29000
        },
    ]

    // Try a revocable payment
    // TXID: b4ad20cad4cc2fcbbec09bc071dfe8c4a4b1e8e57d1e56bf51947445cfc6c7af
    var transaction = stealth.generatePayment(targetPublicKey, myUtxos, 20000, '1RicMooMWxqKczuRCa5D2dnJaUEn9ZJyn', 20000, true, false);
    var txHex = transaction.toHex();
    var check = testRedeem(txHex);

    console.log('Hex: ' + txHex);
    console.log('Found: ',  check);
    console.log();


    myUtxos = [
        {
            index: 0,
            txid: "3d5ceb0f76b7b646d9aaf2b02f67f24a2685311ec277249f126666abbf2a13b6",
            privateKey: "77a8535d57fddfab8470f712ddcbc598c6f481689d91d56b1d90271404aaad2c",
            value: 21000
        },
        {
            index: 0,
            txid: "b637b31cfbf03c85f6704baa2a27df661a9864d71c3c7c6d1a215aa7be4a254e",
            privateKey: "bdf4186692f333f813e8eb828d7b5b0239c94e9dde6ce96fd343f968cb4924e7",
            value: 29000
        },
    ]

    // Try an irrevocable payment
    // TXID: f600643a1d32152117be0d9c652a86dc6182d2dab3be53340739395f524cd95c
    var transaction = stealth.generatePayment(targetPublicKey, myUtxos, 20000, '1RicMooMWxqKczuRCa5D2dnJaUEn9ZJyn', 20000, false, false);
    var txHex = transaction.toHex();
    var check = testRedeem(txHex);

    console.log('Hex: ' + txHex);
    console.log('Found: ',  check);
    console.log();
}

