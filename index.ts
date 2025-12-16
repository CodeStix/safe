import sodium, { from_string } from "libsodium-wrappers";
import pg from "pg";
import fs from "fs";

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
    // id: any;
    id: number;
    fields: {
        [key: string]: SafeField;
    };
}

interface SafeField {
    // key?: Uint8Array;
    version: number;
    nonce: Uint8Array;
    cipher: Uint8Array;
}

interface ObjectKeyStore {
    id: number;
    field: string;
    key: Uint8Array;
    version: number;
    // nonce: number;
}

// class SafeObject {}

class Database {
    db!: pg.Client;
    keyStore: ObjectKeyStore[];

    constructor() {
        this.keyStore = [];
    }

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

    async loadKeyStore() {
        let str;
        try {
            str = fs.readFileSync("keystore", "utf-8");
        } catch {
            str = "";
        }

        const lines = str.split("\n");

        this.keyStore = [];

        for (const line of lines) {
            const split = line.split(" ");
            if (split.length != 4) continue;

            const id = parseInt(split[0]!);
            const field = split[1]!;
            const version = parseInt(split[2]!);
            const key = sodium.from_hex(split[3]!);

            this.keyStore.push({
                id: id,
                field: field,
                version: version,
                key: key,
            });
        }

        // this.keyStore = JSON.parse(fs.readFileSync("keystore.json", "utf-8")) as ObjectKeyStore[];
    }

    async saveKeyStore() {
        const str = [] as string[];

        for (const key of this.keyStore) {
            str.push(`${key.id} ${key.field} ${key.version} ${sodium.to_hex(key.key)}`);
        }

        fs.writeFileSync("keystore", str.join("\n"), "utf-8");
    }

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

    fieldToBytes(v: any) {
        if (typeof v === "string") {
            return new TextEncoder().encode(v);
        } else if (typeof v === "number" && Math.floor(v) === v) {
            const bytes = Buffer.alloc(8);
            bytes.writeBigInt64LE(BigInt(v));
            return bytes;
        } else {
            throw new Error();
        }
    }

    bytesToField(bytes: Uint8Array) {
        return new TextDecoder().decode(bytes);
    }

    async decryptObject(id: number) {
        const rows = await this.db.query(`SELECT * FROM "encrypted" WHERE id = $1`, [id]);
        const row = rows.rows[0];

        if (!row) {
            return null;
        }

        const obj: any = {};

        for (const [k, v] of Object.entries(row)) {
            const storedKey = this.getKey(id, k);
            if (!storedKey) {
                console.warn("No key found to decrypt (" + id + "," + k + ")");
                // throw new Error();
                continue;
            }

            const field = this.unpackField(v as Buffer);

            let key = storedKey.key;

            const requiredRotations = field.version - storedKey.version;
            if (requiredRotations > 0) {
                console.log("Rotate key", requiredRotations, "while decrypting");
                key = this.rotateKey(key, requiredRotations);
                this.storeKey(id, k, key, field.version);
            }

            const bytes = sodium.crypto_aead_chacha20poly1305_decrypt(null, field.cipher, null, field.nonce, key, "uint8array");

            obj[k] = this.bytesToField(bytes);
        }

        return obj;
    }

    getKey(objectId: number, field: string) {
        return this.keyStore.find((e) => e.id === objectId && e.field === field);
    }

    storeKey(objectId: number, field: string, key: Uint8Array, version: number) {
        const existingKey = this.getKey(objectId, field);
        if (existingKey != null) {
            existingKey.key = key;
            existingKey.version = version;
        } else {
            this.keyStore.push({
                field: field,
                id: objectId,
                key: key,
                version: version,
            });
        }
    }

    // getObjectId(safeObject: SafeObject) {
    //     const objectId = safeObject.id;
    //     if (typeof objectId !== "number") throw new Error("Object must have id");
    //     return objectId;
    // }

    rotateKey(key: Uint8Array, times: number) {
        for (let i = 0; i < times; i++) {
            key = sodium.crypto_generichash(sodium.crypto_aead_chacha20poly1305_KEYBYTES, key, null);
        }
        return key;
    }

    unpackField(bytes: Buffer): SafeField {
        const version = Number(bytes.readBigInt64LE(0));
        const nonce = bytes.subarray(8, 8 + sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
        const cipher = bytes.subarray(8 + sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
        return { version, nonce, cipher };
    }

    packField(field: SafeField): Buffer {
        const buffer = Buffer.alloc(8 + sodium.crypto_aead_chacha20poly1305_NPUBBYTES + field.cipher.byteLength);

        buffer.writeBigInt64LE(BigInt(field.version), 0);

        for (let i = 0; i < field.nonce.byteLength; i++) {
            buffer[i + 8] = field.nonce[i]!;
        }

        for (let i = 0; i < field.cipher.byteLength; i++) {
            buffer[i + 8 + sodium.crypto_aead_chacha20poly1305_NPUBBYTES] = field.cipher[i]!;
        }

        return buffer;
    }

    async patchObject(id: number, data: object) {
        // const objectId = this.getObjectId(safeObject);

        const rows = await this.db.query(`SELECT * FROM "encrypted" WHERE id = $1`, [id]);
        const row = rows.rows[0];
        console.log("row", row);

        const fieldValues: any = {};

        for (const [k, v] of Object.entries(data)) {
            // const safeField = safeObject.fields[k];

            // const rows = await this.db.query(`SELECT * FROM "encrypted" WHERE id = $1`, [safeObject.id]);
            // const row = rows.rows[0];
            // console.log("rows", rows.rows);
            // await this.db.query("BEGIN");

            if (row && row[k]) {
                const storedKey = this.getKey(id, k);

                if (!storedKey) throw new Error("Key is required to patch object");

                const safeField = this.unpackField(row[k]);
                // console.log("safeField", safeField);

                const rotateTimes = safeField.version - storedKey.version + 1;
                const newVersion = storedKey.version + rotateTimes;
                const newKey = this.rotateKey(storedKey.key, rotateTimes);

                console.log("Rotate field key when patching", k, rotateTimes);

                this.incrementNonce(safeField.nonce);
                safeField.version = newVersion;
                safeField.cipher = sodium.crypto_aead_chacha20poly1305_encrypt(this.fieldToBytes(v), null, null, safeField.nonce, newKey);

                fieldValues[k] = this.packField(safeField);

                this.storeKey(id, k, newKey, newVersion);
            } else {
                const key = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_KEYBYTES);
                const nonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);

                const version = 1;
                // const nonce = this.nonceToBytes(1);
                const cipher = sodium.crypto_aead_chacha20poly1305_encrypt(this.fieldToBytes(v), null, null, nonce, key);

                const safeField = {
                    nonce: nonce,
                    version: 1,
                    cipher: cipher,
                };
                // safeObject.fields[k] = {
                //     nonce: nonce,
                //     version: 1,
                //     cipher: cipher,
                // };

                console.log("New field key when patching", k);

                fieldValues[k] = this.packField(safeField);

                this.storeKey(id, k, key, version);
            }
        }

        if (row) {
            const sets: string[] = [];
            const values: any[] = [];

            values.push(id);

            let i = 2;
            for (const [k, v] of Object.entries(fieldValues)) {
                sets.push(`"${k}" = $${i++}`);
                values.push(v);
            }

            const query = `UPDATE "encrypted" SET ${sets.join(", ")} WHERE id = $1`;
            console.log("query", query);

            await this.db.query(query, values);
        } else {
            const fields: string[] = [];
            const vals: string[] = [];
            const values: any[] = [];

            fields.push("id");
            vals.push("$1");
            values.push(id);

            let i = 2;
            for (const [k, v] of Object.entries(fieldValues)) {
                fields.push(k);
                vals.push("$" + i);
                values.push(v);
                i++;
            }

            const query = `INSERT INTO "encrypted"(${fields.join(", ")}) VALUES(${vals.join(", ")})`;
            console.log("query", query);
            await this.db.query(query, values);
        }
    }

    incrementNonce(nonceBytes: Uint8Array) {
        if (nonceBytes.byteLength != 8) throw new Error("nonceBytes.byteLength != 8");

        const view = new DataView(nonceBytes.buffer);
        view.setBigUint64(0, view.getBigUint64(0) + 1n); // last 8 bytes
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
    await db.loadKeyStore();
    console.log("Connected");

    // const safeObject: SafeObject = { id: 12, fields: {} };

    const id = 15;

    // await db.patchObject(id, {
    //     title: "nieiuwe notitie",
    //     author: "ik",
    //     content: "dit is een test notitiedit is een test notitiedit is een test notitiedit is een test notitie",
    //     createdat: new Date().getTime(),
    // });

    // db.patchObject(safeObject, {
    //     work: "programmer",
    //     firstName: "Stijn",
    // });

    // db.patchObject(safeObject, {
    //     firstName: "Stijn2",
    // });

    // db.patchObject(safeObject, {
    //     firstName: "Stijn4",
    // });

    console.log(await db.decryptObject(id));

    // Object.entries(safeObject.fields).forEach(([k, v]) => {
    //     console.log(
    //         k.padEnd(10, " "),
    //         "v" + v.version,
    //         "nonce=" + sodium.to_hex(v.nonce),
    //         "cipher=" + sodium.to_hex(v.cipher),
    //         "len=" + v.cipher.byteLength
    //     );
    // });

    // db.keyStore.forEach((e) => {
    //     console.log(e.id, e.field.padEnd(10, " "), "v" + e.version, "key=" + sodium.to_hex(e.key), "len=" + e.key.byteLength);
    // });

    await db.saveKeyStore();
    await db.close();
}

databaseTest();
