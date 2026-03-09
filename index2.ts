import { PrismaPg } from "@prisma/adapter-pg";
import AsyncLock from "async-lock";
import "dotenv/config";
import { IncomingMessage } from "http";
import sodium from "libsodium-wrappers-sumo";
import { RawData, WebSocket, WebSocketServer } from "ws";
import * as z from "zod";
import { Group, PrismaClient } from "./prisma/prisma/client";
import { PrismaPromise } from "@prisma/client/runtime/client";

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

          groupPublicKeyBase64: string;
          groupEncryptedPrivateKeyBase64: string;
          //   groupEncryptedPrivateKeyNonceBase64: string;
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
          tableName: string;
          dataBase64: string;
          nonceBase64: string;
          publicData: any;
          collectionId: string;
          encryptedObjectKeyBase64: string;
          //   encryptedObjectKeyNonceBase64: string;
      }
    | {
          type: "update";
          id: number;
          tableName: string;
          dataBase64?: string;
          nonceBase64?: string;
          publicData?: any;
      }
    | {
          type: "get";
          id: number;
          tableName: string;
      }
    | {
          type: "query";
          tableName: string;
          collectionId: string;
          query: Record<string, any>;
      }
    | {
          type: "get-user-groups";
      }
    | {
          type: "upsert-table";
          tableName: string;
          description: TableColumnDescription[];
      }
    | {
          type: "create-group";
          groupName: string;
          publicKeyBase64: string;
          policies: GroupPolicyDescription[];
      }
    | {
          type: "update-group";
          groupId: string;
          policies: GroupPolicyDescription[];
      };

type GroupPolicyDescription = {
    tableName: string;
    otherGroupId?: string;

    allowReadWrite?: boolean;
    writeFields?: string[];
    allowRead?: boolean;
    readFields?: string[];
    allowRemove?: boolean; // deleting or unsharing object from group
    allowAdd?: boolean; // adding or sharing object with group
};

type TableColumnDescription =
    | {
          type: "TEXT";
          name: string;
          encrypted: boolean;
      }
    | {
          type: "INT";
          name: string;
          encrypted: boolean;
      }
    | {
          type: "BIGINT";
          name: string;
          encrypted: boolean;
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

          publicKeyBase64: string;
          encryptedPrivateKeyNonceBase64: string;
          encryptedPrivateKeyBase64: string;
          encryptionSaltBase64: string;

          //   groupId: string;
          //   groupPublicKeyBase64: string;
          //   groupEncryptedPrivateKeyBase64: string;
          selfGroupId: string;
          groups: {
              id: string;
              publicKeyBase64: string;
              encryptedGroupPrivateKeyBase64: string;
              //   allowCreate: boolean;
              //   allowRead: boolean;
              //   allowWrite: boolean;
          }[];
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
          collectionId?: string;
          encryptedObjectKeyBase64?: string;
          //   encryptedObjectKeyNonceBase64?: string;
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
          data: [
              id: number,
              dataBase64: string,
              nonceBase64: string,
              publicData: any,
              collectionId: string,
              encryptedObjectKeyBase64: string
              //   encryptedObjectKeyNonceBase64: string
          ][];
      }
    | {
          type: "get-user-groups-response";
          request: number;
          selfGroupId: string;
          groups: {
              id: string;
              publicKeyBase64: string;
              encryptedGroupPrivateKeyBase64: string;
              //   allowCreate: boolean;
              //   allowRead: boolean;
              //   allowWrite: boolean;
          }[];
      }
    | {
          type: "upsert-table-response";
          request: number;
      }
    | {
          type: "create-group-response";
          request: number;
          groupId: string;
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
        return await prisma.user.findUnique({
            where: { id: this.userId },
            include: {
                groups: {
                    select: {
                        groupId: true,
                    },
                },
            },
        });
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

                const publicKey = decodeBase64(msg.publicKeyBase64);
                const encryptedPrivateKey = decodeBase64(msg.encryptedPrivateKeyBase64);
                const encryptedPrivateKeyNonce = decodeBase64(msg.encryptedPrivateKeyNonceBase64);
                const encryptionSalt = decodeBase64(msg.encryptionSaltBase64);

                const groupPublicKey = decodeBase64(msg.groupPublicKeyBase64);
                const groupEncryptedPrivateKey = decodeBase64(msg.groupEncryptedPrivateKeyBase64);
                // const groupEncryptedPrivateKeyNonce = decodeBase64(msg.groupEncryptedPrivateKeyNonceBase64);

                const hashedAuthKey = sodium.crypto_generichash(32, authKey, null) as Uint8Array<ArrayBuffer>;

                const user = await this.prisma.$transaction(async (prisma) => {
                    const group = await prisma.group.create({
                        data: {
                            publicKey: groupPublicKey,
                            name: "UserGroup",
                        },
                    });

                    const user = await prisma.user.create({
                        data: {
                            userName: msg.userName,

                            authHashedKey: hashedAuthKey,
                            authSalt: authSalt,

                            publicKey: publicKey,
                            encryptedPrivateKey: encryptedPrivateKey,
                            encryptedPrivateKeyNonce: encryptedPrivateKeyNonce,
                            encryptionSalt: encryptionSalt,

                            selfGroupId: group.id,
                        },
                        select: {
                            id: true,
                        },
                    });

                    await prisma.groupUser.create({
                        data: {
                            encryptedGroupPrivateKey: groupEncryptedPrivateKey,
                            groupId: group.id,
                            userId: user.id,
                        },
                    });

                    return user;
                });

                this.userPerSocket.set(ws, new AuthenticatedUser(ws, user.id));

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
                    select: {
                        id: true,
                        authHashedKey: true,
                        // authSalt: true,
                        encryptedPrivateKey: true,
                        encryptedPrivateKeyNonce: true,
                        encryptionSalt: true,
                        publicKey: true,
                        // selfGroup: {
                        //     select: {
                        //         encryptedGroupPrivateKey: true,
                        //         // encryptedGroupPrivateKeyNonce: true,
                        //         group: {
                        //             select: {
                        //                 id: true,
                        //                 publicKey: true,
                        //             },
                        //         },
                        //     },
                        // },
                        selfGroupId: true,
                        groups: {
                            select: {
                                encryptedGroupPrivateKey: true,
                                // allowCreate: true,
                                // allowRead: true,
                                // allowWrite: true,
                                group: {
                                    select: {
                                        id: true,
                                        publicKey: true,
                                    },
                                },
                            },
                        },
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

                delete (user as any).authHashedKey;

                this.userPerSocket.set(ws, new AuthenticatedUser(ws, user.id));

                wsUser.send({
                    type: "login-response",
                    request: msg.request,

                    publicKeyBase64: encodeBase64(user.publicKey),
                    encryptedPrivateKeyBase64: encodeBase64(user.encryptedPrivateKey),
                    encryptedPrivateKeyNonceBase64: encodeBase64(user.encryptedPrivateKeyNonce),
                    encryptionSaltBase64: encodeBase64(user.encryptionSalt),

                    // groupId: user.selfGroup!.group.id,
                    // groupPublicKeyBase64: encodeBase64(user.selfGroup!.group.publicKey),
                    // groupEncryptedPrivateKeyBase64: encodeBase64(user.selfGroup!.encryptedGroupPrivateKey),
                    selfGroupId: user.selfGroupId,
                    groups: user.groups.map((e) => ({
                        id: e.group.id,
                        publicKeyBase64: encodeBase64(e.group.publicKey),
                        encryptedGroupPrivateKeyBase64: encodeBase64(e.encryptedGroupPrivateKey),
                        // allowCreate: e.allowCreate,
                        // allowRead: e.allowRead,
                        // allowWrite: e.allowWrite,
                    })),
                });
                break;
            }

            case "get-user-groups": {
                if (!user) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Unauthenticated" });
                    break;
                }

                const userObj = await this.prisma.user.findUniqueOrThrow({
                    where: {
                        id: user.id,
                    },
                    select: {
                        selfGroupId: true,
                        groups: {
                            select: {
                                encryptedGroupPrivateKey: true,
                                // allowCreate: true,
                                // allowRead: true,
                                // allowWrite: true,
                                group: {
                                    select: {
                                        id: true,
                                        publicKey: true,
                                    },
                                },
                            },
                        },
                    },
                });

                wsUser.send({
                    type: "get-user-groups-response",
                    request: msg.request,
                    selfGroupId: userObj.selfGroupId,
                    groups: userObj.groups.map((e) => ({
                        id: e.group.id,
                        publicKeyBase64: encodeBase64(e.group.publicKey),
                        encryptedGroupPrivateKeyBase64: encodeBase64(e.encryptedGroupPrivateKey),
                        // allowCreate: e.allowCreate,
                        // allowRead: e.allowRead,
                        // allowWrite: e.allowWrite,
                    })),
                });
                break;
            }

            case "insert": {
                if (!user) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Unauthenticated" });
                    break;
                }

                const objectType = this.getType(msg.tableName);
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

                const userRights = await this.prisma.groupCollection.findFirst({
                    where: {
                        collectionId: msg.collectionId,
                        group: {
                            users: {
                                some: {
                                    userId: user.id,
                                },
                            },
                        },
                        canAdd: true,
                    },
                    select: {
                        readFields: true,
                        writeFields: true,
                    },
                });

                if (!userRights) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Not allowed to add object to collection" });
                    break;
                }

                const encryptedObjectKey = Buffer.from(msg.encryptedObjectKeyBase64, "base64");

                const obj = await this.prisma.object.create({
                    data: {
                        tableName: objectType.name,
                        data: data,
                        nonce: nonce,
                        publicData: publicData,
                        collections: {
                            create: {
                                encryptedObjectKey: encryptedObjectKey,
                                collectionId: msg.collectionId,
                            },
                        },
                    },
                    select: {
                        id: true,
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

                    // const objectType = this.getType(msg.tableName);
                    // if (!objectType) {
                    //     wsUser.send({ type: "error-response", request: msg.request, message: "Unknown type" });
                    //     return;
                    // }

                    const userRights = await this.prisma.groupCollection.findFirst({
                        where: {
                            collection: {
                                objects: {
                                    some: {
                                        objectId: msg.id,
                                    },
                                },
                            },
                            group: {
                                users: {
                                    some: {
                                        userId: user.id,
                                    },
                                },
                            },
                            canWrite: true,
                        },
                        select: {
                            readFields: true,
                            writeFields: true,
                        },
                    });

                    if (!userRights) {
                        wsUser.send({ type: "error-response", request: msg.request, message: "Not allowed to modify object in collection" });
                        return;
                    }

                    const existingObj = await this.prisma.object.findUniqueOrThrow({
                        where: {
                            id: msg.id,
                        },
                        select: {
                            id: true,
                            data: true,
                            nonce: true,
                            publicData: true,
                        },
                    });

                    let data: Buffer<ArrayBuffer> | undefined = undefined;
                    let nonce: Buffer<ArrayBuffer> | undefined = undefined;
                    // let publicData: any | undefined = undefined;

                    if (msg.dataBase64 && msg.nonceBase64) {
                        data = Buffer.from(msg.dataBase64, "base64");
                        nonce = Buffer.from(msg.nonceBase64, "base64");

                        const privateDataMaxSize = 1000; // TODO add somewhere
                        if (nonce.length !== 8 || data.length > privateDataMaxSize) {
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

                    // TODO: validate private data as well
                    const publicData = (existingObj.publicData ?? {}) as any;
                    if (msg.publicData) {
                        for (const k in msg.publicData) {
                            if (userRights.writeFields.length <= 0 || userRights.writeFields.includes(k)) {
                                publicData[k] = msg.publicData[k];
                            }
                        }
                    }

                    // if (typeof msg.publicData !== "undefined") {
                    //     try {
                    //         publicData = objectType.publicDataValidator(msg.publicData);
                    //     } catch (ex) {
                    //         console.error("Could not validate public data", ex);
                    //         wsUser.send({ type: "error-response", request: msg.request, message: "Invalid public data" });
                    //         return;
                    //     }
                    // }

                    await this.prisma.object.update({
                        where: {
                            id: existingObj.id,
                        },
                        data: {
                            data: data,
                            nonce: nonce,
                            publicData: publicData,
                        },
                        // select: {},
                    });

                    wsUser.send({
                        type: "update-response",
                        request: msg.request,
                    });

                    return;
                });

                break;
            }

            case "upsert-table": {
                const columns = (await this.prisma.$queryRaw`SELECT column_name, data_type, is_nullable, column_default
                    FROM information_schema.columns
                    WHERE table_schema = ${"public"}
                    AND table_name = ${msg.tableName}
                    ORDER BY ordinal_position;`) as { column_name: string; data_type: string; is_nullable: string; column_default: string }[];

                const tableName = msg.tableName;
                const groupTableName = tableName + "_Group";

                // console.log("existing columns", columns);
                // const newColumns = msg.description.filter((e) => !columns.some((f) => f.column_name !== e.name));
                // const removedColumns = columns.filter((e) => !msg.description.some((f) => e.column_name !== f.name));

                const transaction = [] as PrismaPromise<any>[];
                transaction.push(
                    this.prisma.$queryRawUnsafe(
                        `CREATE TABLE IF NOT EXISTS "${tableName}"(
                            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                            CONSTRAINT ${tableName}_pkey PRIMARY KEY (id)
                        );
                    `
                    )
                );
                transaction.push(
                    this.prisma.$queryRawUnsafe(`
                        CREATE TABLE IF NOT EXISTS "${groupTableName}"(
                            group_id TEXT NOT NULL,
                            object_id BIGINT NOT NULL,

                            CONSTRAINT ${groupTableName}_pkey 
                                PRIMARY KEY (group_id, object_id),

                            CONSTRAINT ${groupTableName}_group_fk
                                FOREIGN KEY (group_id)
                                REFERENCES "Group"(id)
                                ON DELETE CASCADE,

                            CONSTRAINT ${groupTableName}_object_fk
                                FOREIGN KEY (object_id)
                                REFERENCES "${tableName}"(id)
                                ON DELETE CASCADE
                        );
                    `)
                );

                for (const col of msg.description) {
                    const colType = col.encrypted ? "BYTEA" : col.type;
                    const keyColumnName = col.name + "_key";

                    if (!columns.some((f) => f.column_name !== col.name)) {
                        // New column
                        transaction.push(this.prisma.$queryRawUnsafe(`ALTER TABLE "${tableName}" ADD COLUMN "${col.name}" ${colType}`));
                        if (col.encrypted) {
                            transaction.push(this.prisma.$queryRawUnsafe(`ALTER TABLE "${groupTableName}" ADD COLUMN "${keyColumnName}" BYTEA`));
                        }
                    } else {
                        // Existing column
                        transaction.push(this.prisma.$queryRawUnsafe(`ALTER TABLE "${tableName}" ALTER COLUMN "${col.name}" TYPE ${colType}`));
                    }
                }

                for (const col of columns) {
                    const keyColumnName = col.column_name + "_key";
                    if (!msg.description.some((f) => col.column_name !== f.name)) {
                        // Removed column
                        transaction.push(this.prisma.$queryRawUnsafe(`ALTER TABLE "${tableName}" DROP COLUMN IF EXISTS "${col.column_name}"`));
                        transaction.push(this.prisma.$queryRawUnsafe(`ALTER TABLE "${groupTableName}" DROP COLUMN IF EXISTS "${keyColumnName}"`));
                    }
                }

                transaction.push(
                    this.prisma.tableDescriptor.update({
                        where: {
                            tableName: msg.tableName,
                        },
                        data: {
                            description: msg.description,
                        },
                    })
                );

                await this.prisma.$transaction(transaction);

                wsUser.send({
                    type: "upsert-table-response",
                    request: msg.request,
                });

                break;
            }

            // case "create-group": {
            //     const group = await this.prisma.$transaction(async (prisma) => {
            //         const group = await prisma.group.create({
            //             data: {
            //                 name: msg.groupName,
            //                 publicKey: Buffer.from(msg.publicKeyBase64, "base64"),
            //             },
            //             select: {
            //                 id: true,
            //             },
            //         });

            //         await prisma.groupPolicy.createMany({
            //             data: msg.policies.map((e) => ({
            //                 groupId: group.id,
            //                 otherGroupId: e.otherGroupId ?? group.id,
            //                 tableName: e.tableName,
            //                 allowAdd: e.allowAdd ?? false,
            //                 allowRemove: e.allowRemove ?? false,
            //                 allowRead: e.allowRead ?? false,
            //                 allowReadWrite: e.allowReadWrite ?? false,
            //                 readFields: e.readFields ?? [], // default: empty means all
            //                 writeFields: e.writeFields ?? [], // default: empty means all
            //             })),
            //         });

            //         return group;
            //     });

            //     wsUser.send({
            //         type: "create-group-response",
            //         request: msg.request,
            //         groupId: group.id,
            //     });

            //     break;
            // }

            // case "update-group": {
            //     await this.prisma.groupPolicy.up({
            //         where: {},
            //     });

            //     break;
            // }

            case "query": {
                if (!user) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Unauthenticated" });
                    break;
                }

                const collectionId = msg.collectionId;

                const userRights = await this.prisma.groupCollection.findMany({
                    where: {
                        collectionId: collectionId,
                        group: {
                            users: {
                                some: {
                                    userId: user.id,
                                },
                            },
                        },
                        canRead: true,
                        canQuery: true,
                    },
                    select: {
                        readFields: true,
                        writeFields: true,
                    },
                });

                if (userRights.length <= 0) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Not allowed to query objects in collection" });
                    return;
                }

                // const objectType = this.getType(msg.objectType);
                // if (!objectType) {
                //     wsUser.send({ type: "error-response", request: msg.request, message: "Unknown type" });
                //     break;
                // }

                const queries = [] as { publicData: { path: string[]; equals: string } }[];
                for (const [k, v] of Object.entries(msg.query)) {
                    queries.push({ publicData: { path: [k], equals: v } });
                }

                const obj = await this.prisma.object.findMany({
                    where: {
                        tableName: msg.tableName,
                        collections: {
                            some: {
                                collectionId: collectionId,
                                // collection: {
                                //     groups: {
                                //         some: {
                                //             canQuery: true,
                                //             canRead: true,
                                //             group: {
                                //                 users: {
                                //                     some: {
                                //                         userId: user.id,
                                //                     },
                                //                 },
                                //             },
                                //         },
                                //     },
                                // },
                            },
                        },
                        AND: queries,
                    },
                    select: {
                        id: true,
                        data: true,
                        nonce: true,
                        publicData: true,
                        collections: {
                            where: {
                                collectionId: collectionId,
                            },
                            select: {
                                collectionId: true,
                                encryptedObjectKey: true,
                            },
                        },
                    },
                });

                const convertedData: [
                    id: number,
                    dataBase64: string,
                    nonceBase64: string,
                    publicData: any,
                    collectionId: string,
                    encryptedObjectKeyBase64: string
                    // encryptedObjectKeyNonceBase64: string
                ][] = [];

                for (const row of obj) {
                    const collection = row.collections[0]!;
                    convertedData.push([
                        Number(row.id),
                        Buffer.from(row.data).toString("base64"),
                        Buffer.from(row.nonce).toString("base64"),
                        row.publicData,
                        collection.collectionId,
                        Buffer.from(collection.encryptedObjectKey).toString("base64"),
                        // Buffer.from(group.encryptedObjectKeyNonce).toString("base64"),
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

                // const objectType = this.getType(msg.objectType);
                // if (!objectType) {
                //     wsUser.send({ type: "error-response", request: msg.request, message: "Unknown type" });
                //     break;
                // }

                const userRights = await this.prisma.groupCollection.findMany({
                    where: {
                        collection: {
                            objects: {
                                some: {
                                    objectId: msg.id,
                                },
                            },
                        },
                        group: {
                            users: {
                                some: {
                                    userId: user.id,
                                },
                            },
                        },
                        canRead: true,
                    },
                    select: {
                        collectionId: true,
                        readFields: true,
                        writeFields: true,
                    },
                });

                if (userRights.length <= 0) {
                    wsUser.send({ type: "error-response", request: msg.request, message: "Not allowed to read objects in collection" });
                    break;
                }

                const obj = await this.prisma.object.findUnique({
                    where: {
                        id: msg.id,
                        tableName: msg.tableName,
                    },
                    select: {
                        data: true,
                        nonce: true,
                        publicData: true,
                        collections: {
                            take: 1,
                            where: {
                                collectionId: userRights[0]!.collectionId,
                            },
                            select: {
                                collectionId: true,
                                encryptedObjectKey: true,
                            },
                        },
                    },
                });

                if (obj) {
                    const collection = obj.collections[0]!;
                    wsUser.send({
                        type: "get-response",
                        request: msg.request,
                        dataBase64: Buffer.from(obj.data).toString("base64"),
                        nonceBase64: Buffer.from(obj.nonce).toString("base64"),
                        publicData: obj.publicData,
                        collectionId: collection.collectionId,
                        encryptedObjectKeyBase64: Buffer.from(collection.encryptedObjectKey).toString("base64"),
                        // encryptedObjectKeyNonceBase64: Buffer.from(group.encryptedObjectKeyNonce).toString("base64"),
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

interface ClientGroup {
    id: string;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

class SafeClient<T extends Record<string, ObjectType>> {
    socket: WebSocket;
    responseHandlers = new Map<number, (msg: ClientMessage) => void>();
    keyPerId = new Map<number, StoredKey>();
    objectTypes = new Map<string, ObjectType>();

    private userPublicKey?: Uint8Array;
    private userPrivateKey?: Uint8Array;
    private groups?: ClientGroup[];
    private selfGroupId?: string;

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

        const userKeypair = sodium.crypto_box_keypair();
        const encryptedPrivateKeyNonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
        const encryptedPrivateKey = sodium.crypto_aead_chacha20poly1305_encrypt(
            userKeypair.privateKey,
            null,
            null,
            encryptedPrivateKeyNonce,
            encryptionKey
        );

        const groupKeypair = sodium.crypto_box_keypair();
        // const encryptedGroupPrivateKeyNonce = sodium.randombytes_buf(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
        const encryptedGroupPrivateKey = sodium.crypto_box_seal(groupKeypair.privateKey, userKeypair.publicKey);

        console.timeEnd("register");
        console.log("user keypair", userKeypair);
        console.log("group keypair", groupKeypair);

        const res = await this.request({
            type: "register",
            userName: userName,
            authKeyBase64: encodeBase64(authKey),
            authSaltBase64: encodeBase64(authSalt),
            encryptedPrivateKeyBase64: encodeBase64(encryptedPrivateKey),
            encryptedPrivateKeyNonceBase64: encodeBase64(encryptedPrivateKeyNonce),
            encryptionSaltBase64: encodeBase64(encryptionSalt),
            publicKeyBase64: encodeBase64(userKeypair.publicKey),
            groupPublicKeyBase64: encodeBase64(groupKeypair.publicKey),
            groupEncryptedPrivateKeyBase64: encodeBase64(encryptedGroupPrivateKey),
            // groupEncryptedPrivateKeyNonceBase64: encodeBase64(encryptedGroupPrivateKeyNonce),
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

        // const groupPublicKey = decodeBase64(loginResponse.groupPublicKeyBase64);
        // const groupPrivateKey = sodium.crypto_box_seal_open(decodeBase64(loginResponse.groupEncryptedPrivateKeyBase64), publicKey, privateKey);
        // console.log("group keypair", {
        //     id: loginResponse.groupId,
        //     groupPublicKey,
        //     groupPrivateKey,
        // });

        this.userPublicKey = publicKey;
        this.userPrivateKey = privateKey;
        this.selfGroupId = loginResponse.selfGroupId;

        // this.groupPublicKey = groupPublicKey;
        // this.groupPrivateKey = groupPrivateKey;
        // this.userGroupId = loginResponse.groupId;

        this.groups = loginResponse.groups.map((e) => {
            const groupPublicKey = decodeBase64(e.publicKeyBase64);
            const groupPrivateKey = sodium.crypto_box_seal_open(decodeBase64(e.encryptedGroupPrivateKeyBase64), publicKey, privateKey);
            return {
                id: e.id,
                publicKey: groupPublicKey,
                privateKey: groupPrivateKey,
            };
        });

        console.log("keypair", { publicKey, privateKey });
        console.log("groups", this.groups);

        // for (const group of loginResponse.groups) {
        //     const groupPublicKey = decodeBase64(group.publicKeyBase64);
        //     const groupPrivateKey = sodium.crypto_box_seal_open(decodeBase64(group.encryptedGroupPrivateKeyBase64), publicKey, privateKey);

        //     console.log("group", {
        //         id: group.id,
        //         groupPublicKey,
        //         groupPrivateKey,
        //     });
        // }

        console.timeEnd("login");
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

        const selfGroup = this.getSelfGroup();
        if (!selfGroup) {
            throw new Error("No self group");
        }

        const encryptedObjectKey = sodium.crypto_box_seal(key, selfGroup.publicKey);

        const res = await this.request({
            type: "insert",
            tableName: typeName,
            dataBase64: encodeBase64(cipher),
            nonceBase64: encodeBase64(nonce),
            publicData: publicData,
            encryptedObjectKeyBase64: encodeBase64(encryptedObjectKey),
            groupId: selfGroup.id,
        });
        if (res.type !== "insert-response") {
            throw new Error();
        }

        // await this.storeKey(res.id, {
        //     key: key,
        //     nonce: nonce,
        // });

        return res.id;
    }

    // async getKey(id: number): Promise<StoredKey | undefined> {
    //     return this.keyPerId.get(id);
    // }

    // async storeKey(id: number, key: StoredKey) {
    //     this.keyPerId.set(id, key);
    // }

    async updateRaw(type: string, id: number, privateData: Uint8Array | undefined, publicData: any | undefined) {
        if (typeof privateData === "undefined") {
            if (typeof publicData === "undefined") {
                throw new Error("updateRaw must specify privateData or publicData");
            }

            await this.request({
                type: "update",
                tableName: type,
                publicData: publicData,
                id: id,
            });
            return;
        }

        await sodium.ready;

        // const key = await this.getKey(id);
        // if (!key) {
        //     throw new Error("Cannot update, no key");
        // }

        const getResponse = await this.request({ type: "get", objectType: type, id: id });
        if (getResponse.type !== "get-response") throw new Error();

        if (!getResponse.collectionId || !getResponse.encryptedObjectKeyBase64 || !getResponse.nonceBase64) {
            throw new Error("Object to update not found");
        }

        const group = this.getLocalGroup(getResponse.collectionId);
        if (!group) {
            throw new Error("No object");
        }

        const key = sodium.crypto_box_seal_open(decodeBase64(getResponse.encryptedObjectKeyBase64), group.publicKey, group.privateKey);
        const nonce = nonceToInt(decodeBase64(getResponse.nonceBase64));

        let newNonce = intToNonce(increment64(nonce, 1n));
        // let newKey = rotateKey(key, 1);

        while (true) {
            const cipher = sodium.crypto_aead_chacha20poly1305_encrypt(privateData, null, null, newNonce, key);

            console.log("Encrypt", privateData.length, "->", cipher.length);

            const res = await this.request({
                type: "update",
                tableName: type,
                dataBase64: encodeBase64(cipher),
                nonceBase64: encodeBase64(newNonce),
                publicData: publicData,
                id: id,
            });

            if (res.type === "update-invalid-version") {
                const serverNonce = nonceToInt(decodeBase64(res.nonceBase64));

                // const keyRotateCount = difference64(serverNonce, nonce);
                // if (keyRotateCount > Number.MAX_SAFE_INTEGER) {
                //     throw new Error("Client has newer key than server, shouldn't be possible");
                // }

                // console.log("Rotate key", keyRotateCount, "times in updateRaw", nonce, serverNonce);

                newNonce = intToNonce(increment64(serverNonce, 1n));
                // newKey = rotateKey(newKey, Number(keyRotateCount));
            } else if (res.type === "update-response") {
                // await this.storeKey(id, {
                //     key: newKey,
                //     nonce: newNonce,
                // });
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

    getLocalGroup(id: string) {
        return this.groups?.find((e) => e.id === id);
    }

    getSelfGroup() {
        if (!this.selfGroupId) {
            return undefined;
        }
        return this.getLocalGroup(this.selfGroupId);
    }

    async getRaw(type: string, id: number) {
        await sodium.ready;

        // const key = await this.getKey(id);
        // if (!key) {
        //     throw new Error("No key for " + id);
        // }

        const res = await this.request({ type: "get", objectType: type, id: id });
        if (res.type !== "get-response") {
            throw new Error();
        }

        if (res.dataBase64 && res.nonceBase64 && res.encryptedObjectKeyBase64 && res.collectionId) {
            const cipher = decodeBase64(res.dataBase64);
            const nonce = decodeBase64(res.nonceBase64);

            const group = this.getLocalGroup(res.collectionId);
            if (!group) {
                throw new Error("No local group");
            }

            let ciperKey = sodium.crypto_box_seal_open(decodeBase64(res.encryptedObjectKeyBase64), group.publicKey, group.privateKey);

            // let ciperKey = key.key;

            // const clientNonce = nonceToInt(key.nonce);
            // const serverNonce = nonceToInt(nonce);

            // if (clientNonce != serverNonce) {
            //     const keyRotateCount = difference64(serverNonce, clientNonce);
            //     if (keyRotateCount > Number.MAX_SAFE_INTEGER) {
            //         throw new Error("Client has newer key than server, shouldn't be possible");
            //     }

            //     console.log("Rotate key", keyRotateCount, "times in getRaw", clientNonce, serverNonce);

            //     ciperKey = rotateKey(ciperKey, Number(keyRotateCount));
            //     await this.storeKey(id, {
            //         key: ciperKey,
            //         nonce: nonce,
            //     });
            // }

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

    await client.login("stijn", "Vrijdag1@");

    // await client.update("User", 1, {
    //     private: {
    //         age: 24,
    //         name: "sr",
    //     },
    //     public: {
    //         email: "stijnvantvijfde@gmail.com",
    //     },
    // });

    const user = await client.get("User", 1);
    console.log("obj", user);

    // await client.create("User", {
    //     private: {
    //         name: "stijn",
    //         age: 25,
    //     },
    //     public: {
    //         email: "reddusted@gmail.com",
    //     },
    // });
    // await client.login("stijn2", "Vrijdag1@");

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
