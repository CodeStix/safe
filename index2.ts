import "dotenv/config";
import sodium from "libsodium-wrappers";
import { WebSocket, WebSocketServer, RawData } from "ws";
import { IncomingMessage } from "http";
import { Object, PrismaClient } from "./prisma/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";

type ServerMessage =
    | {
          type: "auth";
          email: string;
      }
    | {
          type: "upsert";
          id?: number | null;
          dataBase64: string;
      }
    | {
          type: "get";
          id: number;
      };

// type ServerRequestMessage = ServerMessage & { request: number };

type ClientMessage =
    | {
          type: "auth-response";
          request: number;
      }
    | {
          type: "upsert-response";
          request: number;
          version: number;
          id: number;
      }
    | {
          type: "get-response";
          request: number;
          dataBase64?: string;
          version?: number;
      }
    | {
          type: "error-response";
          request: number;
          message: string;
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

class SafeServer {
    socket: WebSocketServer;
    prisma: PrismaClient;
    userPerSocket = new Map<WebSocket, AuthenticatedUser>();

    constructor() {
        this.socket = new WebSocketServer({ port: 8080 });
        this.socket.on("connection", this.handleConnection.bind(this));

        const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
        this.prisma = new PrismaClient({ adapter });
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

    async handleMessage(ws: WebSocket, msg: ServerMessage & { request: number }) {
        const wsUser = this.userPerSocket.get(ws) ?? new AuthenticatedUser(ws, undefined);
        const user = await wsUser.getUser(this.prisma);

        switch (msg.type) {
            case "auth": {
                const user = await this.prisma.user.upsert({
                    where: { email: msg.email },
                    create: {
                        email: msg.email,
                        selfGroup: {
                            create: {},
                        },
                    },
                    update: {},
                });
                await this.prisma.groupUserPermission.upsert({
                    where: {
                        userId_groupId: {
                            userId: user.id,
                            groupId: user.selfGroupId,
                        },
                    },
                    create: {
                        userId: user.id,
                        groupId: user.selfGroupId,
                    },
                    update: {},
                });
                this.userPerSocket.set(ws, new AuthenticatedUser(ws, user.id));
                wsUser.send({ type: "auth-response", request: msg.request });
                break;
            }

            case "upsert": {
                if (!user) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Unauthenticated" });
                    break;
                }

                const data = Buffer.from(msg.dataBase64, "base64");

                let obj: Object;
                if (typeof msg.id === "number") {
                    obj = await this.prisma.object.update({
                        where: {
                            id: msg.id,
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
                        data: {
                            data: data,
                            version: {
                                increment: 1,
                            },
                        },
                    });
                } else {
                    obj = await this.prisma.object.create({
                        data: {
                            data: data,
                            version: 1,
                            groups: {
                                create: {
                                    groupId: user.selfGroupId,
                                },
                            },
                        },
                    });
                }

                wsUser.send({
                    type: "upsert-response",
                    request: msg.request,
                    version: Number(obj.version),
                    id: Number(obj.id),
                });
                break;
            }

            case "get": {
                if (!user) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Unauthenticated" });
                    break;
                }

                const obj = await this.prisma.object.findUnique({
                    where: {
                        id: msg.id,
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
                        version: Number(obj.version),
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

function encodeBase64(bytes: Uint8Array): string {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]!);
    }
    return btoa(binary);
}

function decodeBase64(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

class SafeClient {
    socket: WebSocket;
    responseHandlers = new Map<number, (msg: ClientMessage) => void>();

    static currentRequestId: number = 1;

    constructor(url: string) {
        this.socket = new WebSocket(url);
        this.socket.on("open", this.handleConnected.bind(this));
        this.socket.on("message", this.handleMessage.bind(this));
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

    rotateKey(key: Uint8Array, times: number) {
        for (let i = 0; i < times; i++) {
            key = sodium.crypto_generichash(sodium.crypto_aead_chacha20poly1305_KEYBYTES, key, null);
        }
        return key;
    }

    async authenticate(email: string) {
        await this.request({ type: "auth", email: email });
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

    async createRaw(data: Uint8Array): Promise<number> {
        // const key = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_KEYBYTES);
        // const nonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
        // const cipher = sodium.crypto_aead_chacha20poly1305_encrypt(data, null, null, nonce, key);

        const res = await this.request({ type: "upsert", dataBase64: encodeBase64(data) });
        if (res.type !== "upsert-response") {
            throw new Error();
        }

        await sodium.ready;

        console.log("Create response", res);
        // TODO: increment local version and data

        return res.id;
    }

    async updateRaw(id: number, data: Uint8Array) {
        const res = await this.request({ type: "upsert", dataBase64: encodeBase64(data), id: id });
        console.log("Update response", res);

        await sodium.ready;

        // TODO: increment local version and data
    }

    async getRaw(id: number) {
        const res = await this.request({ type: "get", id: id });
        if (res.type !== "get-response") {
            throw new Error();
        }

        await sodium.ready;

        // TODO: increment local version and data
        if (res.dataBase64) {
            const buf = decodeBase64(res.dataBase64);

            return buf;
        } else {
            // Not found
            return null;
        }
    }

    async get<T>(id: number): Promise<T | null> {
        const buf = await this.getRaw(id);
        if (!buf) {
            return null;
        }

        return JSON.parse(new TextDecoder().decode(buf)) as T;
    }

    async create(data: any) {
        return await this.createRaw(new TextEncoder().encode(JSON.stringify(data)));
    }

    async update(id: number, data: any) {
        await this.updateRaw(id, new TextEncoder().encode(JSON.stringify(data)));
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

async function main() {
    const server = new SafeServer();

    const client = new SafeClient("ws://localhost:8080");

    await client.authenticate("reddusted@gmail.com");

    const id = 16;

    let obj = await client.get<{ name: string; age: number }>(id);
    if (!obj) {
        console.log("creating object");
        let id = await client.create({ name: "Rogiest", age: 250 });
        console.log("created", id);
    } else {
        console.log("obj", obj);
        obj = { ...obj, age: obj.age + 1 };
        await client.update(id, obj);

        obj = await client.get<{ name: string; age: number }>(id);
        console.log("updated", obj);
    }
}

main();
