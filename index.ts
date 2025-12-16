import sodium from "libsodium-wrappers";
import pg from "pg";

let nonceCounter = 0;

// class SafeServer {
//     identityKeyPair: sodium.KeyPair;

//     constructor() {
//         this.identityKeyPair = sodium.crypto_kx_keypair();
//     }
// }

// type SessionStart = sodium.KeyPair;

// client.registrations.select("hallo", "yes", "please")

// [cell] <-> [cellpolicy] <-> [group] <-> [groupidentity] <-> [identity]

interface RowPolicy {
    tableName: string;
    rowId: number;
    identityId: number;
}

interface Identity {}

class SafeClient {
    public identityKeyPair: sodium.KeyPair;

    private handshakeKeyPair?: sodium.KeyPair | undefined;

    constructor() {
        this.identityKeyPair = sodium.crypto_sign_keypair();
    }

    beginHandshake() {
        if (this.handshakeKeyPair) throw new Error("Already a handshake in progress");

        this.handshakeKeyPair = sodium.crypto_kx_keypair();

        const signature = sodium.crypto_sign_detached(this.handshakeKeyPair.publicKey, this.identityKeyPair.privateKey, "uint8array");
        return { signature, signedSessionPublicKey: this.handshakeKeyPair.publicKey, identityPublicKey_TODO: this.identityKeyPair.publicKey };
    }

    cancelHandshake() {
        if (this.handshakeKeyPair) {
            sodium.memzero(this.handshakeKeyPair!.privateKey);
            this.handshakeKeyPair = undefined;
        }
    }

    async endHandshake(signedSessionPublicKey: Uint8Array, signature: Uint8Array, clientIdentityPublicKey: Uint8Array, server: boolean) {
        if (sodium.crypto_sign_verify_detached(signature, signedSessionPublicKey, clientIdentityPublicKey)) {
            this.endHandshakeNotSigned(signedSessionPublicKey, server);
        } else {
            throw new Error("Handshake failed, could not verify identity");
        }
    }

    private async endHandshakeNotSigned(clientPublicKey: Uint8Array, server: boolean) {
        const serverSharedSecret = (server ? sodium.crypto_kx_server_session_keys : sodium.crypto_kx_client_session_keys)(
            this.handshakeKeyPair!.publicKey,
            this.handshakeKeyPair!.privateKey,
            clientPublicKey
        );

        // const serverSharedSecretHex = sodium.to_hex(serverSharedSecret.sharedRx);
        // const clientSharedSecretHex = sodium.to_hex(clientSharedSecret.sharedTx);
        // console.log("Match:", serverSharedSecretHex === clientSharedSecretHex);

        this.cancelHandshake();

        console.log("Client secrets");
        console.log("sharedRx", sodium.to_hex(serverSharedSecret.sharedRx));
        console.log("sharedTx", sodium.to_hex(serverSharedSecret.sharedTx));
    }
}

interface SafeObject {
    [key: string]: SafeField;
}

interface SafeField {
    key?: Uint8Array;
    nonce: number;
    cipher: Uint8Array;
}

class SafeObject {}

class Database {
    db!: pg.Client;

    async checkTableExists(schemaName: string, tableName: string) {
        const results = await this.db.query(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2) AS exists;",
            [schemaName, tableName]
        );

        return results.rows[0].exists;
    }

    // async createTestTable() {
    //     await this.db.query("CREATE TABLE test (article_id bigserial primary key, article_name varchar(20) NOT NULL, article_desc text NOT NULL, date_added timestamp default NULL);");
    // }

    async init() {
        this.db = new pg.Client("postgresql://postgres:postgres@localhost:5432/safe?schema=public");
        await this.db.connect();

        // const exists = await this.checkTableExists();
        // if (!exists) {
        // }
        // console.log({ exists });
    }

    async close() {
        await this.db.end();
    }

    // async createObject(tableName: string, data: object): Promise<SafeObject> {
    //     let obj: SafeObject = {};

    //     for (const [k, v] of Object.entries(data)) {
    //         // Each cell gets a seperate key, nonce and ciphertext
    //         const key = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_KEYBYTES);

    //         const nonce = 1;
    //         const nonceBytes = this.nonceToBytes(nonce);

    //         // let bytes;
    //         // if (typeof v === "string") {
    //         //     bytes = new TextEncoder().encode(v);
    //         // } else if (typeof v === "number" && Math.floor(v) === v) {
    //         //     bytes = Buffer.alloc(4);
    //         //     bytes.writeInt32LE(v);
    //         // } else {
    //         //     throw new Error();
    //         // }

    //         const cipher = sodium.crypto_aead_chacha20poly1305_encrypt(bytes, null, null, nonceBytes, key);

    //         console.log(tableName, ":", k.padEnd(10, " "), "key", sodium.to_hex(key), "nonce", nonce, "cipher", sodium.to_hex(cipher));

    //         obj[k] = {
    //             cipher: cipher,
    //             nonce: nonce,
    //             key: key,
    //         };
    //     }

    //     return obj;
    // }

    fieldToBytes(v: any) {
        if (typeof v === "string") {
            return new TextEncoder().encode(v);
        } else if (typeof v === "number" && Math.floor(v) === v) {
            const bytes = Buffer.alloc(4);
            bytes.writeInt32LE(v);
            return bytes;
        } else {
            throw new Error();
        }
    }

    async patchObject(safeObject: SafeObject, data: object) {
        for (const [k, v] of Object.entries(data)) {
            const safeField = safeObject[k];

            if (safeField) {
                if (!safeField.key) throw new Error("Key is required to patch object");

                safeField.nonce += 1;
                safeField.key = sodium.crypto_generichash(sodium.crypto_aead_chacha20poly1305_KEYBYTES, safeField.key, null);
                safeField.cipher = sodium.crypto_aead_chacha20poly1305_encrypt(
                    this.fieldToBytes(v),
                    null,
                    null,
                    this.nonceToBytes(safeField.nonce),
                    safeField.key
                );
            } else {
                const key = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_KEYBYTES);
                const nonce = 1;
                const cipher = sodium.crypto_aead_chacha20poly1305_encrypt(this.fieldToBytes(v), null, null, this.nonceToBytes(nonce), key);

                const safeField: SafeField = {
                    key: key,
                    nonce: nonce,
                    cipher: cipher,
                };
                safeObject[k] = safeField;
            }
        }
    }

    nonceToBytes(n: number) {
        const nonce = new Uint8Array(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
        const view = new DataView(nonce.buffer);
        view.setBigUint64(0, BigInt(n)); // last 8 bytes
        return nonce;
    }
}

async function keyExchangeTest() {
    await sodium.ready;

    const clientA = new SafeClient();
    const clientB = new SafeClient();

    const handshakeA = clientA.beginHandshake();
    const handshakeB = clientB.beginHandshake();

    clientA.endHandshake(handshakeB.signedSessionPublicKey, handshakeB.signature, handshakeB.identityPublicKey_TODO, true);
    clientB.endHandshake(handshakeA.signedSessionPublicKey, handshakeA.signature, handshakeA.identityPublicKey_TODO, false);
}

// keyExchangeTest();

function getNonce() {
    const counter = ++nonceCounter;
    const nonce = new Uint8Array(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
    const view = new DataView(nonce.buffer);
    view.setBigUint64(0, BigInt(counter)); // last 8 bytes
    return nonce;
}

async function diffieHellmanKeyExchange() {
    await sodium.ready;

    console.time("Key generation");

    const serverKeyPair = sodium.crypto_kx_keypair();
    const clientKeyPair = sodium.crypto_kx_keypair();

    const serverSharedSecret = sodium.crypto_kx_server_session_keys(serverKeyPair.publicKey, serverKeyPair.privateKey, clientKeyPair.publicKey);

    const clientSharedSecret = sodium.crypto_kx_client_session_keys(clientKeyPair.publicKey, clientKeyPair.privateKey, serverKeyPair.publicKey);

    console.timeEnd("Key generation");

    const serverSharedSecretHex = sodium.to_hex(serverSharedSecret.sharedRx);
    const clientSharedSecretHex = sodium.to_hex(clientSharedSecret.sharedTx);
    console.log("Match:", serverSharedSecretHex === clientSharedSecretHex);

    const nonce = getNonce();

    // console.log("nonce", nonce);

    console.time("Send/receive");

    const message = sodium.crypto_aead_chacha20poly1305_encrypt("", null, null, nonce, clientSharedSecret.sharedTx, "uint8array");

    console.log("encrypted", message);

    const decryptedMessage = sodium.crypto_aead_chacha20poly1305_decrypt(null, message, null, nonce, serverSharedSecret.sharedRx, "text");

    console.timeEnd("Send/receive");

    console.log("decryptedMessage", decryptedMessage);
}

/*
when rows in the database are shared with a new identity, the ratched is rotated

access control is a connection between an identity group and a row (identity <-> identity group <-> row)
access control fields:
- 
- editable columns
- which 
*/

// diffieHellmanKeyExchange();

async function databaseTest() {
    const db = new Database();
    await db.init();
    console.log("Connected");

    const safeObject: SafeObject = {};

    await db.patchObject(safeObject, {
        firstName: "stijn",
        lastName: "rogiest",
        age: 20,
    });

    // const obj = await db.createObject("testing", {
    //     firstName: "stijn",
    //     lastName: "rogiest",
    //     age: 20,
    // });
    console.log(safeObject);

    await db.close();
}

databaseTest();
