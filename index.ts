import sodium from "libsodium-wrappers";

let nonceCounter = 0;

// class SafeServer {
//     identityKeyPair: sodium.KeyPair;

//     constructor() {
//         this.identityKeyPair = sodium.crypto_kx_keypair();
//     }
// }

// type SessionStart = sodium.KeyPair;

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

async function keyExchangeTest() {
    await sodium.ready;

    const clientA = new SafeClient();
    const clientB = new SafeClient();

    const handshakeA = clientA.beginHandshake();
    const handshakeB = clientB.beginHandshake();

    clientA.endHandshake(handshakeB.signedSessionPublicKey, handshakeB.signature, handshakeB.identityPublicKey_TODO, true);
    clientB.endHandshake(handshakeA.signedSessionPublicKey, handshakeA.signature, handshakeA.identityPublicKey_TODO, false);
}

keyExchangeTest();

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

    const message = sodium.crypto_aead_chacha20poly1305_encrypt(
        "hallo joepie kjadfjkladfljkadfksjl",
        null,
        null,
        nonce,
        clientSharedSecret.sharedTx,
        "uint8array"
    );

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
