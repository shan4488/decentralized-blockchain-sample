# decentralized-blockchain-sample
Decentralized blockchain sample implementaion

Code:

import crypto from "crypto";

class Block {
    timestamp: string;
    transaction: Transaction;
    previousHash: string;
    hash: string;
    nonce: number;

    constructor(previousHash: string, transaction: Transaction) {
        this.timestamp = new Date().toISOString();
        this.transaction = transaction;
        this.previousHash = previousHash;
        this.nonce = 0;
        this.hash = this.calculateHash();
    }

    calculateHash(): string {
        return crypto
            .createHash('sha256')
            .update(this.previousHash + this.timestamp + JSON.stringify(this.transaction) + this.nonce)
            .digest('hex');
    }
}

class Blockchain {
    chain: Block[];

    constructor() {
        this.chain = [this.createGenesisBlock()];
    }

    createGenesisBlock(): Block {
        return new Block('', new Transaction(100, 'genesis', 'satoshi'));
    }

    getLastBlock(): Block {
        return this.chain[this.chain.length - 1];
    }

    addBlock(block: Block) {
        if (block.previousHash !== this.getLastBlock().hash) {
            throw new Error("Invalid block: previous hash does not match.");
        }

        // Validate Proof of Work
        if (!block.hash.startsWith('0000')) {
            throw new Error("Invalid block: proof of work is incorrect.");
        }

        // Validate Transaction Signature
        if (!block.transaction.verifySignature()) {
            throw new Error("Invalid block: signature verification failed.");
        }

        this.chain.push(block);
    }
}

class Miner {
    blockchain: Blockchain;

    constructor(blockchain: Blockchain) {
        this.blockchain = blockchain;
    }

    mineTransaction(transaction: Transaction) {
        const previousBlock = this.blockchain.getLastBlock();
        const newBlock = new Block(previousBlock.hash, transaction);

        while (!newBlock.hash.startsWith('0000')) {
            newBlock.nonce++;
            newBlock.hash = newBlock.calculateHash();
        }

        console.log(`Block mined: ${newBlock.hash}`);
        this.blockchain.addBlock(newBlock);
    }
}

class Transaction {
    amount: number;
    fromAddress: string;
    toAddress: string;
    signature: string | null = null;

    constructor(amount: number, fromAddress: string, toAddress: string) {
        this.amount = amount;
        this.fromAddress = fromAddress;
        this.toAddress = toAddress;
    }

    signTransaction(signingKey: crypto.KeyObject) {
        if (signingKey.asymmetricKeyType !== "rsa" && signingKey.asymmetricKeyType !== "ec") {
            throw new Error("Cannot sign transactions with a non-valid key.");
        }

        if (this.fromAddress !== signingKey.asymmetricKeyDetails?.publicKey) {
            throw new Error("You cannot sign transactions for other wallets.");
        }

        const sign = crypto.createSign('SHA256');
        sign.update(this.toString()).end();

        this.signature = sign.sign(signingKey).toString('hex');
    }

    verifySignature(): boolean {
        if (!this.signature || this.fromAddress === '') return true; // Genesis block

        const verify = crypto.createVerify('SHA256');
        verify.update(this.toString());

        return verify.verify(this.fromAddress, Buffer.from(this.signature, 'hex'));
    }

    toString(): string {
        return JSON.stringify(this);
    }
}

class Wallet {
    publicKey: string;
    privateKey: crypto.KeyObject;

    constructor() {
        const keyPair = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });

        this.privateKey = keyPair.privateKey;
        this.publicKey = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    }

    createTransaction(amount: number, recipient: string): Transaction {
        const transaction = new Transaction(amount, this.publicKey, recipient);
        transaction.signTransaction(this.privateKey);
        return transaction;
    }
}

// Usage example
const myBlockchain = new Blockchain();
const miner = new Miner(myBlockchain);
const aliceWallet = new Wallet();
const bobWallet = new Wallet();

const transaction1 = aliceWallet.createTransaction(50, bobWallet.publicKey);
miner.mineTransaction(transaction1);

console.log(JSON.stringify(myBlockchain, null, 2));
