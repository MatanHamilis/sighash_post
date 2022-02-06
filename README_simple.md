# One *single* trick to lose all your coins

In this post we will be discussing an old bug in Bitcoin, typically referred to as the "SIGHASH_SINGLE" bug.

NOTICE: This is the simpler version of a longer, more technical post about this bug, which can be found [HERE](./README.md).

## The Bug

### When does it appear?

Transactions in Bitcoin have *inputs* and *outputs*. The outputs specify the destinations and amounts of the coins transacted while the inputs specify the coins spent in the transaction.

When you want to send some coins the your friend, your friend enters his/her Bitcoin wallet, copy his/her address and send it back to you.
Next, you paste this address into your wallet, specify the amount of coins you wish to send to your friend and confirm the transaction.

So what is this address?
While is may look like total nonsense, it is used to represent a lock which only the owner of the address can lock/unlock and everyone else can verify that that locking procedure was done properly.
When sending coins to an address, the coins that were sent can only be spent using a secret key associated with the address specified.
The amount and the address are, therefore, specified in the *output* portion of the transactions.

Then, to spend a coin in Bitcoin, the spender specifies the origin of the coin, that is, in which output of which transaction were these coins received.
Remember, the referred coins have this "lock" attached to them which only the owner of the address has the key to this lock.

To accomplish the spending, the spender proves that he/she owns the coins in question.
This is done by taking **all the data of the transaction** (inputs and outputs) and "locking" it using the key.

This is why keeping track of your Bitcoin key is very important - losing it implies the inability to spend your coins!

To make the spending policy is Bitcoin more expressive, Bitcoin allows locking only some parts of the transaction and not all of it.
This makes sense because without the key, neither locking all of the transactions nor just a small part of it should be possible.

One of these options allows the spender to lock the inputs of the transaction alongside only a *single* output, rather than locking all of them(this option is known as `SIGHASH_SINGLE`).

The bug occurs when Bitcoin handles the scenario in which the single output which should be locked doesn't exist.
In that case the "proof" associated with the spending of the keys doesn't depend on any of the data and can be reused in other transaction.

### What are the implications?

First, we have to keep in mind that all such proofs stay on the blockchain and are therefore public.
Therefore, this proof generated in the buggy edge case can be reused to spend all the coins owned by the address which mistakenly has generated this proof.

Using this proof, an attacker will be able to also steal any funds moved into this address in the future.

### Am I vulnerable? Should I worry?

This bug exists from the very first days of Bitcoin and was introduced into the code by Satoshi Nakamoto (the pseudonym used by the inventor of Bitcoin).
There is evidence dating to 2012 of people being aware of this bug, however this bug was never fixed and it exists in Bitcoin until this day!

To be exact, the only addresses vulnerable to this attack are old addresses known as "P2PKH" addresses.
In 2017 an upgrade was introduced to Bitcoin known as SegWit in which new types of addresses can be created. These addresses start with "bc1" and are no longer vulnerable to the bug and can be used safely.

### How can this bug be exploited?

Consider "wallet-connect", a browser extension very similar in nature to "MetaMask" which can support various coins, one of which is Bitcoin.
Many new projects support wallet-connect integration with which various crypto-wallets can be directly used to interact with these projects almost seamlessly.
Such projects typically ask the user to approve transactions and sign them using the wallet-connect extension.
Before the user approves the transaction, the wallet and extension present the user the contents of the transaction, including amounts, destinations and additional data relevant to the transaction.

In a possible scenario, such a transaction may cause this Bitcoin bug, and users are expected to confirm it because the transaction itself might seem harmless. After all, the transaction simply asks the user to move some funds from the to another address.
However, since the transaction would also result the bug being triggered and the user creating such reusable proof, the funds of the user could be stolen by an attacker at any time in the future, so even if the team of the project would "fix" the issue causing the transactions to contain this Bitcoin bug, users remain vulnerable until they move their funds to another address.