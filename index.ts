import sodium from "libsodium-wrappers";

let nonceCounter = 0;

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

diffieHellmanKeyExchange();
