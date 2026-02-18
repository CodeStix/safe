import "dotenv/config";
import sodium from "libsodium-wrappers-sumo";
import { WebSocket, WebSocketServer, RawData } from "ws";
import { IncomingMessage } from "http";
import { PrismaClient } from "./prisma/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import AsyncLock from "async-lock";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/client";
import { ObjectCreateInput } from "./prisma/prisma/models";
import * as z from "zod";

// type ObjectTypeName = string;

type ServerMessage =
    // | {
    //       type: "auth";
    //       email: string;
    //   }
    | {
          type: "register";
          userName: string;

          authSaltBase64: string;
          authKeyBase64: string;

          encryptionSaltBase64: string;
          // Do not send encryptionKey!

          publicKeyBase64: string;
          encryptedPrivateKeyBase64: string;
          encryptedPrivateKeyNonceBase64: string;
      }
    | {
          type: "get-user";
          userName: string;
      }
    | {
          type: "login";
          userName: string;
          authKeyBase64: string;
      }
    | {
          type: "insert";
          objectType: string;
          dataBase64: string;
          nonceBase64: string;
          publicData: any;
      }
    | {
          type: "update";
          id: number;
          objectType: string;
          dataBase64?: string;
          nonceBase64?: string;
          publicData?: any;
      }
    | {
          type: "get";
          id: number;
          objectType: string;
      }
    | {
          type: "query";
          objectType: string;
          query: Record<string, any>;
      };

// type ServerRequestMessage = ServerMessage & { request: number };

type ClientMessage =
    // | {
    //       type: "auth-response";
    //       request: number;
    //   }
    | {
          type: "register-response";
          request: number;
      }
    | {
          type: "get-user-response";
          request: number;
          authSaltBase64?: string;
      }
    | {
          type: "login-response";
          request: number;
          encryptionSaltBase64: string;
          publicKeyBase64: string;
          encryptedPrivateKeyNonceBase64: string;
          encryptedPrivateKeyBase64: string;
      }
    | {
          type: "insert-response";
          request: number;
          //   version: number;
          id: number;
      }
    | {
          type: "update-invalid-version";
          request: number;
          nonceBase64: string;
          //   version: number;
      }
    | {
          type: "update-response";
          request: number;
      }
    | {
          type: "get-response";
          request: number;
          dataBase64?: string;
          nonceBase64?: string;
          publicData?: any;
          //   version?: number;
      }
    | {
          type: "error-response";
          request: number;
          message: string;
      }
    | {
          type: "query-response";
          request: number;
          data: [id: number, dataBase64?: string, nonceBase64?: string, publicData?: any][];
      };

class AuthenticatedUser {
    constructor(public socket: WebSocket, public userId: string | undefined) {}

    send(msg: ClientMessage) {
        this.socket.send(JSON.stringify(msg));
    }

    async getUser(prisma: PrismaClient) {
        if (!this.userId) {
            return null;
        }
        return await prisma.user.findUnique({ where: { id: this.userId } });
    }
}

type ObjectValidator<T> = (data: unknown) => unknown;

type ObjectType<K extends string = string, Private = any, Public = any> = {
    name: K;
    privateDataMaxSize: number;
    privateDataValidator: ObjectValidator<Private>;
    publicDataValidator: ObjectValidator<Public>;
    // publicDataTransformer?: ObjectValidator;
};

class SafeServer {
    socket: WebSocketServer;
    prisma: PrismaClient;
    userPerSocket = new Map<WebSocket, AuthenticatedUser>();
    lock: AsyncLock;
    objectTypes = new Map<string, Omit<ObjectType, "privateDataValidator">>();

    constructor(settings: SafeSettings<any>) {
        this.socket = new WebSocketServer({ port: 8080 });
        this.socket.on("connection", this.handleConnection.bind(this));

        const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
        this.prisma = new PrismaClient({ adapter });

        this.lock = new AsyncLock();

        this.objectTypes = new Map(Object.entries(settings.objectTypes));
    }

    // registerType(type: Omit<ObjectType, "privateDataValidator">) {
    //     this.objectTypes.set(type.name, type);
    // }

    getType(typeName: string) {
        return this.objectTypes.get(typeName);
    }

    handleConnection(ws: WebSocket, request: IncomingMessage) {
        console.log("New connection", request.socket.remoteAddress);

        ws.on("message", (data, isBinary) => {
            this.handleRawMessage(ws, data, isBinary);
        });
        ws.on("close", (code, reason) => {
            this.handleCloseConnection(ws, code, reason);
        });
    }

    handleCloseConnection(ws: WebSocket, code: number, reason: Buffer) {
        console.log("Lost connection", code, reason);

        this.userPerSocket.delete(ws);
    }

    handleRawMessage(ws: WebSocket, data: RawData, isBinary: boolean) {
        if (isBinary) {
            return;
        }

        let msg: ServerMessage & { request: number };
        try {
            msg = JSON.parse(data.toString("utf-8"));
        } catch (ex) {
            console.error("Could not parse message", data);
            return;
        }

        // TODO: prevent multiple messages at once per ws
        this.handleMessage(ws, msg);
    }

    // async getUserSaltOrRandomSalt(userName: string) {
    //     const user = await this.prisma.user.findUnique({
    //         where: {
    //             userName: userName,
    //         },
    //     });

    //     if (!user) {
    //         return sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    //     } else {
    //         return user.authSalt;
    //     }
    // }

    async handleMessage(ws: WebSocket, msg: ServerMessage & { request: number }) {
        const wsUser = this.userPerSocket.get(ws) ?? new AuthenticatedUser(ws, undefined);
        const user = await wsUser.getUser(this.prisma);

        switch (msg.type) {
            // case "auth": {
            //     const user = await this.prisma.user.upsert({
            //         where: { email: msg.email },
            //         create: {
            //             email: msg.email,
            //             selfGroup: {
            //                 create: {},
            //             },
            //         },
            //         update: {},
            //     });
            //     await this.prisma.groupUserPermission.upsert({
            //         where: {
            //             userId_groupId: {
            //                 userId: user.id,
            //                 groupId: user.selfGroupId,
            //             },
            //         },
            //         create: {
            //             userId: user.id,
            //             groupId: user.selfGroupId,
            //         },
            //         update: {},
            //     });
            //     this.userPerSocket.set(ws, new AuthenticatedUser(ws, user.id));
            //     wsUser.send({ type: "auth-response", request: msg.request });
            //     break;
            // }

            case "register": {
                const authKey = decodeBase64(msg.authKeyBase64);
                const authSalt = decodeBase64(msg.authSaltBase64);
                const encryptionSalt = decodeBase64(msg.encryptionSaltBase64);
                const publicKey = decodeBase64(msg.publicKeyBase64);
                const encryptedPrivateKey = decodeBase64(msg.encryptedPrivateKeyBase64);
                const encryptedPrivateKeyNonce = decodeBase64(msg.encryptedPrivateKeyNonceBase64);

                const hashedAuthKey = sodium.crypto_generichash(32, authKey, null) as Uint8Array<ArrayBuffer>;

                await this.prisma.user.create({
                    data: {
                        userName: msg.userName,

                        authHashedKey: hashedAuthKey,
                        authSalt: authSalt,

                        publicKey: publicKey,
                        encryptedPrivateKey: encryptedPrivateKey,
                        encryptedPrivateKeyNonce: encryptedPrivateKeyNonce,
                        encryptionSalt: encryptionSalt,

                        selfGroup: {
                            create: {
                                publicKey: new Uint8Array(), // TODO
                            },
                        },
                    },
                });

                wsUser.send({ type: "register-response", request: msg.request });

                break;
            }

            case "get-user": {
                const user = await this.prisma.user.findUnique({
                    where: {
                        userName: msg.userName,
                    },
                });

                wsUser.send({
                    type: "get-user-response",
                    request: msg.request,
                    authSaltBase64: user ? encodeBase64(user.authSalt) : undefined,
                });
                break;
            }

            case "login": {
                const authKey = decodeBase64(msg.authKeyBase64);
                const hashedAuthKey = sodium.crypto_generichash(32, authKey, null);

                const user = await this.prisma.user.findUnique({
                    where: {
                        userName: msg.userName,
                    },
                });

                if (!user) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Unknown user" });
                    break;
                }

                if (sodium.compare(user.authHashedKey, hashedAuthKey) !== 0) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Invalid password" });
                    break;
                }

                wsUser.send({
                    type: "login-response",
                    request: msg.request,
                    encryptedPrivateKeyBase64: encodeBase64(user.encryptedPrivateKey),
                    encryptedPrivateKeyNonceBase64: encodeBase64(user.encryptedPrivateKeyNonce),
                    encryptionSaltBase64: encodeBase64(user.encryptionSalt),
                    publicKeyBase64: encodeBase64(user.publicKey),
                });

                break;
            }

            case "insert": {
                if (!user) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Unauthenticated" });
                    break;
                }

                const objectType = this.getType(msg.objectType);
                if (!objectType) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Unknown type" });
                    break;
                }

                const data = Buffer.from(msg.dataBase64, "base64");
                const nonce = Buffer.from(msg.nonceBase64, "base64");

                if (nonce.length !== 8 || data.length > objectType.privateDataMaxSize) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Invalid private data" });
                    break;
                }

                let publicData: any | undefined = undefined;

                if (typeof msg.publicData !== "undefined") {
                    try {
                        publicData = objectType.publicDataValidator(msg.publicData);
                    } catch (ex) {
                        console.error("Could not validate public data", ex);
                        wsUser.send({ type: "error-response", request: msg.request, message: "Invalid public data" });
                        break;
                    }
                }

                const obj = await this.prisma.object.create({
                    data: {
                        type: objectType.name,
                        data: data,
                        nonce: nonce,
                        publicData: publicData,
                        groups: {
                            create: {
                                groupId: user.selfGroupId,
                                encryptedObjectKey: new Uint8Array(), // TODO
                            },
                        },
                    },
                });

                wsUser.send({
                    type: "insert-response",
                    request: msg.request,
                    id: Number(obj.id),
                });
                break;
            }

            case "update": {
                await this.lock.acquire(String(msg.id), async () => {
                    if (!user) {
                        wsUser.send({ type: "error-response", request: msg.request, message: "Unauthenticated" });
                        return;
                    }

                    const objectType = this.getType(msg.objectType);
                    if (!objectType) {
                        wsUser.send({ type: "error-response", request: msg.request, message: "Unknown type" });
                        return;
                    }

                    const existingObj = await this.prisma.object.findUniqueOrThrow({
                        where: {
                            id: msg.id!,
                            type: objectType.name,
                            groups: {
                                some: {
                                    allowWrite: true,
                                    group: {
                                        users: {
                                            some: {
                                                userId: user.id,
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    });

                    let data: Buffer<ArrayBuffer> | undefined = undefined;
                    let nonce: Buffer<ArrayBuffer> | undefined = undefined;
                    let publicData: any | undefined = undefined;

                    if (msg.dataBase64 && msg.nonceBase64) {
                        data = Buffer.from(msg.dataBase64, "base64");
                        nonce = Buffer.from(msg.nonceBase64, "base64");

                        if (nonce.length !== 8 || data.length > objectType.privateDataMaxSize) {
                            wsUser.send({ type: "error-response", request: msg.request, message: "Invalid private data" });
                            return;
                        }

                        const existingNonceInt = nonceToInt(existingObj.nonce);
                        const nonceInt = nonceToInt(nonce);
                        if (nonceInt !== existingNonceInt + 1n) {
                            wsUser.send({
                                type: "update-invalid-version",
                                request: msg.request,
                                nonceBase64: Buffer.from(existingObj.nonce).toString("base64"),
                            });
                            return;
                        }
                    }

                    if (typeof msg.publicData !== "undefined") {
                        try {
                            publicData = objectType.publicDataValidator(msg.publicData);
                        } catch (ex) {
                            console.error("Could not validate public data", ex);
                            wsUser.send({ type: "error-response", request: msg.request, message: "Invalid public data" });
                            return;
                        }
                    }

                    await this.prisma.object.update({
                        where: {
                            id: existingObj.id,
                        },
                        data: {
                            data: data,
                            nonce: nonce,
                            publicData: publicData,
                        },
                    });

                    wsUser.send({
                        type: "update-response",
                        request: msg.request,
                    });

                    return;
                });

                break;
            }

            case "query": {
                if (!user) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Unauthenticated" });
                    break;
                }

                const objectType = this.getType(msg.objectType);
                if (!objectType) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Unknown type" });
                    break;
                }

                const queries = [] as { publicData: { path: string[]; equals: string } }[];
                for (const [k, v] of Object.entries(msg.query)) {
                    queries.push({ publicData: { path: [k], equals: v } });
                }

                const obj = await this.prisma.object.findMany({
                    where: {
                        type: objectType.name,
                        groups: {
                            some: {
                                allowRead: true,
                                group: {
                                    users: {
                                        some: {
                                            userId: user.id,
                                        },
                                    },
                                },
                            },
                        },
                        AND: queries,
                    },
                    select: {
                        id: true,
                        data: true,
                        nonce: true,
                        publicData: true,
                    },
                });

                const convertedData: [id: number, dataBase64?: string, nonceBase64?: string, publicData?: any][] = [];

                for (const row of obj) {
                    convertedData.push([
                        Number(row.id),
                        Buffer.from(row.data).toString("base64"),
                        Buffer.from(row.nonce).toString("base64"),
                        row.publicData,
                    ]);
                }

                wsUser.send({
                    type: "query-response",
                    request: msg.request,
                    data: convertedData,
                });

                break;
            }

            case "get": {
                if (!user) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Unauthenticated" });
                    break;
                }

                const objectType = this.getType(msg.objectType);
                if (!objectType) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Unknown type" });
                    break;
                }

                const obj = await this.prisma.object.findUnique({
                    where: {
                        id: msg.id,
                        type: objectType.name,
                        groups: {
                            some: {
                                allowRead: true,
                                group: {
                                    users: {
                                        some: {
                                            userId: user.id,
                                        },
                                    },
                                },
                            },
                        },
                    },
                });

                if (obj) {
                    wsUser.send({
                        type: "get-response",
                        request: msg.request,
                        dataBase64: Buffer.from(obj.data).toString("base64"),
                        nonceBase64: Buffer.from(obj.nonce).toString("base64"),
                        publicData: obj.publicData as object,
                    });
                } else {
                    wsUser.send({
                        type: "get-response",
                        request: msg.request,
                    });
                }

                break;
            }

            default: {
                console.log("Unhandled server message", msg);
                break;
            }
        }
    }
}

const MASK64 = (1n << 64n) - 1n;

function nonceToInt(nonce: Uint8Array): bigint {
    if (nonce.length !== 8) {
        throw new Error("Expected exactly 8 bytes");
    }

    let n = 0n;
    for (const b of nonce) {
        n = (n << 8n) | BigInt(b);
    }
    return n;
}

function intToNonce(n: bigint): Uint8Array {
    const bytes = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) {
        bytes[i] = Number(n & 0xffn);
        n >>= 8n;
    }
    return bytes;
}

function increment64(a: bigint, b: bigint): bigint {
    return (a + b) & MASK64;
}

function difference64(a: bigint, b: bigint): bigint {
    return (a - b) & MASK64;
}

function encodeBase64(bytes: Uint8Array): string {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]!);
    }
    return btoa(binary);
}

function decodeBase64(base64: string): Uint8Array<ArrayBuffer> {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function compareBufferSameTime(a: Uint8Array, b: Uint8Array) {
    if (a.length !== b.length) return false;

    let same = true;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            same = false;
        }
    }

    return same;
}

// function incrementNonce(nonce: Uint8Array): Uint8Array {
//     if (nonce.byteLength != 8) throw new Error("nonceBytes.byteLength != 8");

//     const newNonce = new Uint8Array(8);
//     const newNonceView = new DataView(newNonce.buffer);

//     const nonceView = new DataView(nonce.buffer);
//     newNonceView.setBigUint64(0, nonceView.getBigUint64(0) + 1n); // last 8 bytes

//     return newNonce;
// }

function rotateKey(key: Uint8Array, times: number) {
    for (let i = 0; i < times; i++) {
        key = sodium.crypto_generichash(sodium.crypto_aead_chacha20poly1305_KEYBYTES, key, null);
    }
    return key;
}

type StoredKey = {
    key: Uint8Array;
    nonce: Uint8Array;
    // version: number;
};

type GetSafeData<T> = T extends ObjectType<any, infer Private, infer Public> ? { private: Private; public: Public } : never;

type SafeDataQuery<T> = T extends ObjectType<any, infer Private, infer Public>
    ? {
          public?: {
              [K in keyof Public]: Public[K] extends string | number ? Public[K] : never;
          };
          private?: {
              [K in keyof Private]: Private[K] extends string | number ? Private[K] : never;
          };
      }
    : never;

class SafeSettings<T> {
    objectTypes: Record<string, ObjectType>;

    constructor(objectTypes?: Record<string, ObjectType>) {
        this.objectTypes = objectTypes ?? {};
    }

    withType<K extends string, Private, Public>(
        objectType: ObjectType<K, Private, Public>
    ): SafeSettings<
        T & {
            [P in K]: ObjectType<P, Private, Public>;
        }
    > {
        return new SafeSettings({
            ...this.objectTypes,
            [objectType.name]: objectType,
        });
    }

    set<K extends keyof T>(t: K, data: GetSafeData<T[K]>) {}
}

// const f = new SafeSettings().withType(zodToType("User", User)).withType(zodToType("Profile", Profile));
// f.set("User");

class SafeClient<T extends Record<string, ObjectType>> {
    socket: WebSocket;
    responseHandlers = new Map<number, (msg: ClientMessage) => void>();
    keyPerId = new Map<number, StoredKey>();
    objectTypes = new Map<string, ObjectType>();

    static currentRequestId: number = 1;

    constructor(url: string, settings: SafeSettings<T>) {
        this.objectTypes = new Map(Object.entries(settings.objectTypes));

        this.socket = new WebSocket(url);
        this.socket.on("open", this.handleConnected.bind(this));
        this.socket.on("message", this.handleMessage.bind(this));
    }

    // registerType(type: ObjectType) {
    //     this.objectTypes.set(type.name, type);
    // }

    getType(typeName: string) {
        return this.objectTypes.get(typeName);
    }

    handleConnected() {
        console.log("connecetd");
    }

    send(message: ServerMessage) {
        if (this.socket.readyState === WebSocket.OPEN) {
            console.log("====>", JSON.stringify(message));
            this.socket.send(JSON.stringify(message));
        } else {
            this.socket.once("open", () => this.send(message));
        }
    }

    deriveKey(password: Uint8Array | string, salt: Uint8Array) {
        return sodium.crypto_pwhash(
            32,
            password,
            salt,
            sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
            sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
            sodium.crypto_pwhash_ALG_ARGON2ID13
        );
    }

    async register(userName: string, password: string) {
        await sodium.ready;

        console.time("register");

        const authSalt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
        const encryptionSalt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);

        const authKey = this.deriveKey(password, authSalt);
        const encryptionKey = this.deriveKey(password, encryptionSalt);

        const identityKeypair = sodium.crypto_box_keypair();

        const encryptedPrivateKeyNonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
        const encryptedPrivateKey = sodium.crypto_aead_chacha20poly1305_encrypt(
            identityKeypair.privateKey,
            null,
            null,
            encryptedPrivateKeyNonce,
            encryptionKey
        );

        console.timeEnd("register");
        console.log("keypair", identityKeypair);

        const res = await this.request({
            type: "register",
            userName: userName,
            authKeyBase64: encodeBase64(authKey),
            authSaltBase64: encodeBase64(authSalt),
            encryptedPrivateKeyBase64: encodeBase64(encryptedPrivateKey),
            encryptedPrivateKeyNonceBase64: encodeBase64(encryptedPrivateKeyNonce),
            encryptionSaltBase64: encodeBase64(encryptionSalt),
            publicKeyBase64: encodeBase64(identityKeypair.publicKey),
        });
        if (res.type !== "register-response") throw new Error();
    }

    async login(userName: string, password: string) {
        await sodium.ready;

        const getUserResponse = await this.request({
            type: "get-user",
            userName: userName,
        });
        if (getUserResponse.type !== "get-user-response") throw new Error();

        if (typeof getUserResponse.authSaltBase64 !== "string") {
            throw new Error("User not found");
        }

        const authSalt = decodeBase64(getUserResponse.authSaltBase64);
        const authKey = this.deriveKey(password, authSalt);

        const loginResponse = await this.request({
            type: "login",
            userName: userName,
            authKeyBase64: encodeBase64(authKey),
        });
        if (loginResponse.type !== "login-response") throw new Error();

        console.time("login");

        const encryptionSalt = decodeBase64(loginResponse.encryptionSaltBase64);
        const publicKey = decodeBase64(loginResponse.publicKeyBase64);
        const encryptedPrivateKeyNonce = decodeBase64(loginResponse.encryptedPrivateKeyNonceBase64);
        const encryptedPrivateKey = decodeBase64(loginResponse.encryptedPrivateKeyBase64);

        const encryptionKey = this.deriveKey(password, encryptionSalt);

        const privateKey = sodium.crypto_aead_chacha20poly1305_decrypt(null, encryptedPrivateKey, null, encryptedPrivateKeyNonce, encryptionKey);

        console.timeEnd("login");
        console.log("keypair", { publicKey, privateKey });
    }

    async request(msg: ServerMessage) {
        const res = await new Promise<ClientMessage>((resHandler) => {
            let m = msg as ServerMessage & { request: number };
            let reqId = SafeClient.currentRequestId++;
            m.request = reqId;
            this.send(m);
            this.responseHandlers.set(reqId, resHandler);
        });

        if (res.type === "error-response") {
            throw new Error("Received error-response: " + res.message);
        }

        return res;
    }

    async createRaw(typeName: string, privateData: Uint8Array, publicData: any | undefined): Promise<number> {
        await sodium.ready;

        const key = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_KEYBYTES);
        const nonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);

        const cipher = sodium.crypto_aead_chacha20poly1305_encrypt(privateData, null, null, nonce, key);

        console.log("Encrypt", privateData.length, "->", cipher.length);

        console.log("Create key size", key.length, "nonce size", nonce.length, "nonce", nonceToInt(nonce));

        const res = await this.request({
            type: "insert",
            objectType: typeName,
            dataBase64: encodeBase64(cipher),
            nonceBase64: encodeBase64(nonce),
            publicData: publicData,
            // version: 1,
        });
        if (res.type !== "insert-response") {
            throw new Error();
        }

        await this.storeKey(res.id, {
            key: key,
            nonce: nonce,
        });

        return res.id;
    }

    async getKey(id: number): Promise<StoredKey | undefined> {
        return this.keyPerId.get(id);
    }

    async storeKey(id: number, key: StoredKey) {
        this.keyPerId.set(id, key);
    }

    async updateRaw(type: string, id: number, privateData: Uint8Array | undefined, publicData: any | undefined) {
        if (typeof privateData === "undefined") {
            if (typeof publicData === "undefined") {
                throw new Error("updateRaw must specify privateData or publicData");
            }

            await this.request({
                type: "update",
                objectType: type,
                publicData: publicData,
                id: id,
            });
            return;
        }

        await sodium.ready;

        const key = await this.getKey(id);
        if (!key) {
            throw new Error("Cannot update, no key");
        }

        const clientNonce = nonceToInt(key.nonce);

        let newNonce = intToNonce(increment64(clientNonce, 1n));
        let newKey = rotateKey(key.key, 1);

        while (true) {
            const cipher = sodium.crypto_aead_chacha20poly1305_encrypt(privateData, null, null, newNonce, newKey);

            console.log("Encrypt", privateData.length, "->", cipher.length);

            const res = await this.request({
                type: "update",
                objectType: type,
                dataBase64: encodeBase64(cipher),
                nonceBase64: encodeBase64(newNonce),
                publicData: publicData,
                id: id,
            });

            if (res.type === "update-invalid-version") {
                const serverNonce = nonceToInt(decodeBase64(res.nonceBase64));

                const keyRotateCount = difference64(serverNonce, clientNonce);
                if (keyRotateCount > Number.MAX_SAFE_INTEGER) {
                    throw new Error("Client has newer key than server, shouldn't be possible");
                }

                console.log("Rotate key", keyRotateCount, "times in updateRaw", clientNonce, serverNonce);

                newNonce = intToNonce(increment64(serverNonce, 1n));
                newKey = rotateKey(newKey, Number(keyRotateCount));
            } else if (res.type === "update-response") {
                await this.storeKey(id, {
                    key: newKey,
                    nonce: newNonce,
                });
                break;
            } else {
                throw new Error();
            }
        }
    }

    async queryRaw(type: string, publicQuery: Record<string, any>) {
        const res = await this.request({ type: "query", objectType: type, query: publicQuery });
        if (res.type !== "query-response") {
            throw new Error();
        }
    }

    async getRaw(type: string, id: number) {
        await sodium.ready;

        const key = await this.getKey(id);
        if (!key) {
            throw new Error("No key for " + id);
        }

        const res = await this.request({ type: "get", objectType: type, id: id });
        if (res.type !== "get-response") {
            throw new Error();
        }

        if (res.dataBase64 && res.nonceBase64) {
            const cipher = decodeBase64(res.dataBase64);
            const nonce = decodeBase64(res.nonceBase64);

            let ciperKey = key.key;

            const clientNonce = nonceToInt(key.nonce);
            const serverNonce = nonceToInt(nonce);

            if (clientNonce != serverNonce) {
                const keyRotateCount = difference64(serverNonce, clientNonce);
                if (keyRotateCount > Number.MAX_SAFE_INTEGER) {
                    throw new Error("Client has newer key than server, shouldn't be possible");
                }

                console.log("Rotate key", keyRotateCount, "times in getRaw", clientNonce, serverNonce);

                ciperKey = rotateKey(ciperKey, Number(keyRotateCount));
                await this.storeKey(id, {
                    key: ciperKey,
                    nonce: nonce,
                });
            }

            const data = sodium.crypto_aead_chacha20poly1305_decrypt(null, cipher, null, nonce, ciperKey, "uint8array");

            return { private: data, public: res.publicData };
        } else {
            // Not found
            return null;
        }
    }

    async get<K extends keyof T & string>(type: K, id: number): Promise<GetSafeData<T[K]> | null> {
        const objectType = this.getType(type);
        if (!objectType) {
            throw new Error("Unknown type " + type);
        }

        const objData = await this.getRaw(type, id);
        if (!objData) {
            return null;
        }

        let privateData = JSON.parse(new TextDecoder().decode(objData.private));

        try {
            privateData = objectType.privateDataValidator(privateData);
        } catch (ex) {
            throw new Error("Could not validate private data: " + String(ex));
        }

        // Make sure to validate public data (actually only done to run transformers)
        let publicData = objData.public;
        try {
            publicData = objectType.publicDataValidator(publicData);
        } catch (ex) {
            throw new Error("Could not validate public data: " + String(ex));
        }

        return { private: privateData, public: publicData } as GetSafeData<T[K]>;
    }

    // async query<K extends keyof T & string>(type: K, query: SafeDataQuery<T[K]>): Promise<GetSafeData<T[K]>[]> {}

    async create<K extends keyof T & string>(type: K, data: GetSafeData<T[K]>) {
        const objectType = this.getType(type);
        if (!objectType) {
            throw new Error("Unknown type " + type);
        }

        let privateData: any;
        try {
            privateData = objectType.privateDataValidator(data.private);
        } catch (ex) {
            throw new Error("Could not validate private data: " + String(ex));
        }

        let publicData: any | undefined = undefined;
        if (typeof data.public !== "undefined") {
            try {
                publicData = objectType.publicDataValidator(data.public);
            } catch (ex) {
                throw new Error("Could not validate public data: " + String(ex));
            }
        }

        return await this.createRaw(type, new TextEncoder().encode(JSON.stringify(privateData)), publicData);
    }

    async update<K extends keyof T & string>(type: K, id: number, data: Partial<GetSafeData<T[K]>>) {
        const objectType = this.getType(type);
        if (!objectType) {
            throw new Error("Unknown type " + type);
        }

        let privateData: any | undefined = undefined;
        if (typeof data.private !== "undefined") {
            try {
                privateData = objectType.privateDataValidator(data.private);
            } catch (ex) {
                throw new Error("Could not validate private data: " + String(ex));
            }
        }

        let publicData: any | undefined = undefined;
        if (typeof data.public !== "undefined") {
            try {
                publicData = objectType.publicDataValidator(data.public);
            } catch (ex) {
                throw new Error("Could not validate public data: " + String(ex));
            }
        }

        await this.updateRaw(type, id, privateData === undefined ? undefined : new TextEncoder().encode(JSON.stringify(privateData)), publicData);
    }

    handleMessage(data: RawData, isBinary: boolean) {
        console.log("<====", data.toString("utf-8"));

        const message = JSON.parse(data.toString()) as ClientMessage;
        if ("request" in message) {
            // Request response
            const handler = this.responseHandlers.get(message.request);
            if (handler) {
                this.responseHandlers.delete(message.request);
                handler(message);
            } else {
                console.error("Unknown request response", message);
            }
        } else {
            console.log("Unhandled client message", message);
        }
    }

    // handleOpen()
}

function zodToType<K extends string, Schema extends z.ZodObject<{ public: z.ZodType; private: z.ZodType }>>(
    typeName: K,
    schema: Schema
): ObjectType<K, ReturnType<Schema["shape"]["private"]["parse"]>, ReturnType<Schema["shape"]["public"]["parse"]>> {
    return {
        name: typeName,
        privateDataMaxSize: 100,
        privateDataValidator: schema.shape.private.parse,
        publicDataValidator: schema.shape.public.parse,
    };
}

async function main() {
    // const UserEmailContainer

    const User = z.object({
        public: z.object({
            email: z.string(),
        }),
        private: z.object({
            name: z.string(),
            age: z.number(),
        }),
    });

    const Profile = z.object({
        public: z.null(),
        private: z.object({
            imageUrl: z.string(),
        }),
    });

    const settings = new SafeSettings().withType(zodToType("User", User)).withType(zodToType("Profile", Profile));

    const server = new SafeServer(settings);
    // server.registerType(zodToType("User", User));

    // User.

    // let a: z.input<typeof Person>["name"]

    const client = new SafeClient("ws://localhost:8080", settings);

    // await client.login("stijn", "Vrijdag1@");
    await client.login("stijn", "Vrijdag1@");

    return;

    // client.create("Profile", {
    //     private: {
    //         imageUrl: "",
    //     },
    //     public: null,
    // });
    // client.registerType(zodToType("User", User));

    // await client.authenticate("reddusted@gmail.com");
    // await client.register()

    // const users = await client.query("User", {
    //     public: {
    //         email: "",
    //     },
    // });

    let id = await client.create("User", {
        private: {
            name: "Stijn Rogiest",
            age: 25,
        },
        public: {
            email: "reddusted@gmail.com",
        },
    });

    let obj = await client.get("User", id);
    // console.log("obj", obj);

    await client.update("User", id, {
        private: { name: obj!.private.name + "!!!!", age: obj!.private.age + 1 },
        public: { email: "reddusted200@gmail.com" },
    });

    // obj = await client.get("User", id);

    await client.update("User", id, {
        private: {
            name: obj!.private.name + "!!!!",
            age: obj!.private.age + 1,
        },
    });
}

main();
