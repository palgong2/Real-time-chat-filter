// index.js
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { pool } = require("./db");
const os = require("os");

// AWS SDK v3 - SNS, SQS
const { SNSClient, PublishCommand } = require("@aws-sdk/client-sns");
const {
  SQSClient,
  ReceiveMessageCommand,
  DeleteMessageCommand,
} = require("@aws-sdk/client-sqs");

// ===== 환경 변수 / 기본 설정 =====
const {
  JWT_SECRET = "dev-secret-change-later",
  AWS_REGION = "us-east-1",
  CHAT_SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:883579328882:CHAT-TOPIC", // 채팅 브로드캐스트용 SNS 토픽
  CHAT_SQS_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/883579328882/CHAT-QUEUE", // 각 인스턴스가 읽을 SQS 큐
  NOTIFY_SNS_TOPIC_ARN, // 정지 알림용 SNS 토픽 (메일 발송 등)
} = process.env;

const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const {
  DynamoDBDocumentClient,
  PutCommand,
  QueryCommand,
} = require("@aws-sdk/lib-dynamodb");

async function getRecentRoomChats(roomId, limit = 10) {
  try {
    const resp = await ddb.send(
      new QueryCommand({
        TableName: CHAT_TABLE,
        KeyConditionExpression: "roomId = :r",
        ExpressionAttributeValues: {
          ":r": String(roomId),
        },
        ScanIndexForward: false, // sentAt 내림차순 (최근것 먼저)
        Limit: limit,
      })
    );
    return resp.Items || [];
  } catch (err) {
    console.error("최근 방 채팅 조회 실패:", err);
    return [];
  }
}

const DDB_REGION = AWS_REGION; // us-east-1
const CHAT_TABLE = process.env.CHAT_TABLE_NAME || "ChatMessages";

const ddbClient = new DynamoDBClient({ region: DDB_REGION });
const ddb = DynamoDBDocumentClient.from(ddbClient, {
  marshallOptions: { removeUndefinedValues: true },
});

// 인스턴스 ID는 환경변수가 있으면 그걸 쓰고,
// 없으면 hostname 을 사용해서 인스턴스별로 서로 다르게 만든다.
const INSTANCE_ID = process.env.INSTANCE_ID || os.hostname();

// AWS 클라이언트
const sns = new SNSClient({ region: AWS_REGION });
const sqs = CHAT_SQS_QUEUE_URL ? new SQSClient({ region: AWS_REGION }) : null;

// Express 앱 생성
const app = express();
app.use(express.json());

// ----- CORS 허용 (S3 프론트에서 오는 요청용) -----
app.use((req, res, next) => {
  // 프론트 S3 웹사이트 도메인
  const allowedOrigin =
    "http://abuse-chat-frontend-22360034.s3-website-us-east-1.amazonaws.com";

  res.header("Access-Control-Allow-Origin", allowedOrigin);
  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
  );
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // 프리플라이트(OPTIONS)는 여기서 바로 200 반환
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  next();
});

// ---------------- 욕설 필터 관련 ----------------
const PROFANITY_LIST = [
  { pattern: "욕1", score: 5 },
  { pattern: "욕2", score: 10 },
  { pattern: "욕3", score: 20 },
];

function normalizeMessage(msg) {
  if (!msg) return "";
  return msg
    .toLowerCase()
    .replace(/\s+/g, "")
    .replace(/[^\w가-힣]/g, "");
}

function evaluateMessage(original) {
  const normalized = normalizeMessage(original);
  let totalScore = 0;
  let masked = original;

  for (const item of PROFANITY_LIST) {
    const word = item.pattern;
    const score = item.score;
    if (!word) continue;

    if (normalized.includes(word)) {
      totalScore += score;

      const re = new RegExp(word, "gi");
      masked = masked.replace(re, "***");
    }
  }

  return { score: totalScore, maskedMessage: masked };
}

async function saveChatToDynamo({
  roomId,
  userId,
  nickname,
  original,
  masked,
  score,
  instanceId,
}) {
  const sentAt = new Date().toISOString();

  const item = {
    roomId: String(roomId),
    sentAt, // sort key
    messageId: sentAt, // 간단하게 sentAt 재사용
    userId,
    nickname,
    original,
    masked,
    score: Number(score || 0),
    instanceId: instanceId || INSTANCE_ID,
  };

  try {
    await ddb.send(
      new PutCommand({
        TableName: CHAT_TABLE,
        Item: item,
      })
    );
  } catch (err) {
    console.error("DynamoDB 저장 실패:", err);
  }
}

// ---------------- RDS 쪽 유저/제재/로그 ----------------
async function getRecentAbuseLogs(userId, limit = 5) {
  const [rows] = await pool.query(
    `
    SELECT room_id, original_message, masked_message, score, created_at
    FROM abuse_logs
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT ?
    `,
    [userId, limit]
  );
  return rows;
}

async function sendBanNotificationViaSNS(user, abuseLogId, roomId, score) {
  if (!NOTIFY_SNS_TOPIC_ARN) {
    console.log("[WARN] NOTIFY_SNS_TOPIC_ARN 미설정 - 정지 알림 SNS 미발송");
    return;
  }

  try {
    const logs = await getRecentAbuseLogs(user.id, 5);

    // ★ 여기 추가: 최근 방 채팅 10개 끌어오기
    const recentChats = await getRecentRoomChats(roomId, 10);
    // 오래된 것부터 보이게 순서 뒤집기
    const orderedChats = recentChats.slice().reverse();

    const logLines = logs.map((l, idx) => {
      const t = new Date(l.created_at).toISOString();
      return [
        `  [${idx + 1}] 시간: ${t}`,
        `      방 ID: ${l.room_id}`,
        `      점수: ${l.score}`,
        `      원본: ${l.original_message}`,
        `      마스킹: ${l.masked_message}`,
      ].join("\n");
    });

    // ★ 여기: 최근 채팅 문맥
    const contextLines =
      orderedChats.length > 0
        ? orderedChats.map((c, idx) => {
            const t = c.sentAt || "";
            const text = c.masked || c.original || "";
            return `  [${idx + 1}] ${t}  ${c.nickname}: ${text}`;
          })
        : ["  (기록 없음)"];

    const messageLines = [
      "[Abuse Chat Filter] 계정 정지 알림",
      "",
      "■ 사용자 정보",
      `- 닉네임: ${user.nickname}`,
      `- 이메일: ${user.email}`,
      `- userId: ${user.id}`,
      "",
      "■ 정지 트리거",
      `- roomId: ${roomId}`,
      `- 이번 메시지 점수: ${score}`,
      abuseLogId
        ? `- abuse_log_id: ${abuseLogId}`
        : "- abuse_log_id: (저장 실패 또는 없음)",
      "",
      "■ 최근 욕설 로그 (최신 5건)",
      logLines.length > 0 ? logLines.join("\n") : "  (기록 없음)",
      "",
      "■ 최근 방 채팅 (문맥용, 최신 10건)",
      contextLines.join("\n"),
      "",
      `정지 시각: ${new Date().toISOString()}`,
    ];

    const textMessage = messageLines.join("\n");

    await sns.send(
      new PublishCommand({
        TopicArn: NOTIFY_SNS_TOPIC_ARN,
        Subject: `[AbuseChat] 계정 정지 - ${user.nickname}`,
        Message: textMessage,
      })
    );

    console.log("[INFO] 정지 알림 SNS 발송 완료:", user.email);
  } catch (err) {
    console.error("정지 알림 SNS 발송 실패:", err);
  }
}

async function logAbuse({ userId, roomId, original, masked, score }) {
  if (score <= 0) return null;

  try {
    const [result] = await pool.query(
      "INSERT INTO abuse_logs (user_id, room_id, original_message, masked_message, score) VALUES (?, ?, ?, ?, ?)",
      [userId, roomId, original, masked, score]
    );
    return result.insertId;
  } catch (err) {
    console.error("욕설 로그 저장 실패:", err);
    return null;
  }
}

async function findUserById(userId) {
  const [rows] = await pool.query(
    "SELECT id, email, nickname, penalty_points, is_banned, mute_until FROM users WHERE id = ?",
    [userId]
  );
  const row = rows[0];
  if (!row) return null;

  return {
    id: row.id,
    email: row.email,
    nickname: row.nickname,
    penaltyPoints: row.penalty_points ?? 0,
    isBanned: !!row.is_banned,
    muteUntil: row.mute_until ? new Date(row.mute_until) : null,
  };
}

async function applyPenalty(user, score, abuseLogId = null, roomId = null) {
  if (!user || score <= 0) return null;

  let newPenaltyPoints = (user.penaltyPoints ?? 0) + score;
  let newIsBanned = !!user.isBanned;
  let newMuteUntil = user.muteUntil ?? null;
  let result = null;

  const isSevereMessage = score >= 15;

  if (newPenaltyPoints >= 20 || isSevereMessage) {
    newIsBanned = true;
    newMuteUntil = null;
    result = "banned";
  } else if (newPenaltyPoints >= 10) {
    newMuteUntil = new Date(Date.now() + 5 * 60 * 1000);
    result = "muted";
  } else if (newPenaltyPoints >= 5) {
    result = "warn";
  }

  await pool.query(
    "UPDATE users SET penalty_points = ?, is_banned = ?, mute_until = ? WHERE id = ?",
    [newPenaltyPoints, newIsBanned ? 1 : 0, newMuteUntil, user.id]
  );

  user.penaltyPoints = newPenaltyPoints;
  user.isBanned = newIsBanned;
  user.muteUntil = newMuteUntil;

  if (result === "banned") {
    // ban_events 기록
    const [res] = await pool.query(
      "INSERT INTO ban_events (user_id, abuse_log_id, room_id, score) VALUES (?, ?, ?, ?)",
      [user.id, abuseLogId, roomId, score]
    );
    console.log("[INFO] ban_events 기록:", res.insertId);

    // SNS로 정지 알림
    await sendBanNotificationViaSNS(user, abuseLogId, roomId, score);
  }

  return result;
}

function isUserMuted(user) {
  if (!user || !user.muteUntil) return false;
  return user.muteUntil > new Date();
}

// ---------------- 정적 파일/헬스체크 ----------------
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (req, res) => {
  res.send("ok");
});

app.get("/whoami", (req, res) => {
  res.json({ instanceId: INSTANCE_ID });
});

// ---------------- REST: 회원가입 / 로그인 ----------------
app.post("/auth/register", async (req, res) => {
  const { email, password, nickname } = req.body;

  if (!email || !password || !nickname) {
    return res
      .status(400)
      .json({ message: "email, password, nickname 은 필수입니다." });
  }

  try {
    const [rows] = await pool.query("SELECT id FROM users WHERE email = ?", [
      email,
    ]);
    if (rows.length > 0) {
      return res.status(409).json({ message: "이미 사용 중인 이메일입니다." });
    }

    const passwordHash = bcrypt.hashSync(password, 10);

    const [result] = await pool.query(
      "INSERT INTO users (email, password_hash, nickname) VALUES (?, ?, ?)",
      [email, passwordHash, nickname]
    );

    return res.status(201).json({
      message: "회원가입 성공",
      userId: result.insertId,
      nickname,
    });
  } catch (err) {
    console.error("회원가입 에러:", err);
    return res.status(500).json({ message: "서버 에러" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "email, password 는 필수입니다." });
  }

  try {
    const [rows] = await pool.query(
      "SELECT id, email, password_hash, nickname, is_banned, penalty_points, mute_until, is_admin FROM users WHERE email = ?",
      [email]
    );
    if (rows.length === 0) {
      return res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." });
    }

    const user = rows[0];
    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) {
      return res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." });
    }

    if (user.is_banned) {
      return res
        .status(403)
        .json({ message: "정지된 계정입니다. 로그인할 수 없습니다." });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        nickname: user.nickname,
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.json({
      message: "로그인 성공",
      token,
      userId: user.id,
      nickname: user.nickname,
      isAdmin: !!user.is_admin,
    });
  } catch (err) {
    console.error("로그인 에러:", err);
    return res.status(500).json({ message: "서버 에러" });
  }
});

// ---------------- HTTP 서버 + Socket.IO ----------------
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" },
});

// 소켓 인증
io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token) {
    return next(new Error("인증 토큰이 없습니다."));
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.data.userId = payload.userId;
    socket.data.nickname = payload.nickname;
    return next();
  } catch (err) {
    console.error("소켓 인증 실패:", err.message);
    return next(new Error("인증 실패"));
  }
});

// ---------------- SQS Poller (SNS → SQS → 모든 인스턴스) ----------------
function startChatPoller() {
  if (!sqs || !CHAT_SQS_QUEUE_URL) {
    console.log(
      "[WARN] CHAT_SQS_QUEUE_URL 미설정 - SQS 기반 브로드캐스트 비활성화"
    );
    return;
  }

  console.log("[INFO] SQS Poller 시작:", CHAT_SQS_QUEUE_URL);

  const WAIT_SECONDS = 10;
  let pollerEnabled = true;

  (async function loop() {
    while (pollerEnabled) {
      try {
        const resp = await sqs.send(
          new ReceiveMessageCommand({
            QueueUrl: CHAT_SQS_QUEUE_URL,
            MaxNumberOfMessages: 10,
            WaitTimeSeconds: WAIT_SECONDS,
          })
        );

        const messages = resp.Messages || [];
        if (messages.length === 0) {
          continue;
        }

        for (const m of messages) {
          try {
            let bodyObj;
            try {
              bodyObj = JSON.parse(m.Body);
            } catch (e) {
              console.error("SQS 메시지 JSON 파싱 실패:", e);
              continue;
            }

            // SNS → SQS 구독이면 바디가 SNS envelope 형태
            let payload;
            if (bodyObj.Type === "Notification" && bodyObj.Message) {
              try {
                payload = JSON.parse(bodyObj.Message);
              } catch (e) {
                console.error("SNS Message JSON 파싱 실패:", e);
                continue;
              }
            } else {
              payload = bodyObj;
            }

            if (!payload || payload.type !== "chat") {
              // 우리가 정의한 채팅 타입이 아니면 무시
              continue;
            }

            // 자기 인스턴스에서 보낸 건 이미 local emit 했으므로 스킵
            if (payload.originInstanceId === INSTANCE_ID) {
              continue;
            }

            const roomId = payload.roomId;
            if (!roomId) continue;

            io.to(String(roomId)).emit("chat:receive", {
              nickname: payload.nickname || "익명",
              message: payload.message || "",
              userId: payload.userId || null,
              messageId: payload.messageId || null,
            });
          } finally {
            // 성공/실패 상관없이 일단 삭제 (재처리 원치 않음)
            try {
              await sqs.send(
                new DeleteMessageCommand({
                  QueueUrl: CHAT_SQS_QUEUE_URL,
                  ReceiptHandle: m.ReceiptHandle,
                })
              );
            } catch (e) {
              console.error("SQS 메시지 삭제 실패:", e);
            }
          }
        }
      } catch (err) {
        console.error("SQS Poller 에러:", err);

        // 자격 증명 문제면 무한 로그 방지 위해 Poller 중지
        if (err.name === "CredentialsProviderError") {
          console.error(
            "[FATAL] AWS 자격 증명 오류. SQS Poller를 중지합니다. " +
              "EC2 IAM Role / Policy를 확인한 후 서비스를 재시작해야 합니다."
          );
          pollerEnabled = false;
        }
      }
    }
  })();
}

// ---------------- Socket.IO 이벤트 ----------------
io.on("connection", (socket) => {
  console.log(
    "새 클라이언트 연결됨:",
    socket.id,
    "userId:",
    socket.data.userId
  );

  socket.on("user:status", async () => {
    try {
      const userId = socket.data.userId;
      if (!userId) {
        socket.emit("user:status-result", {
          ok: false,
          message: "인증 정보가 없습니다.",
        });
        return;
      }

      const user = await findUserById(userId);
      if (!user) {
        socket.emit("user:status-result", {
          ok: false,
          message: "사용자를 찾을 수 없습니다.",
        });
        return;
      }

      socket.emit("user:status-result", {
        ok: true,
        penaltyPoints: user.penaltyPoints,
        isBanned: user.isBanned,
        muteUntil: user.muteUntil ? user.muteUntil.toISOString() : null,
      });
    } catch (err) {
      console.error("user:status 에러:", err);
      socket.emit("user:status-result", {
        ok: false,
        message: "상태 조회 중 오류가 발생했습니다.",
      });
    }
  });

  socket.on("room:create", async ({ name }) => {
    const trimmed = (name || "").trim();
    if (!trimmed) {
      socket.emit("room:create-result", {
        ok: false,
        message: "방 이름은 필수입니다.",
      });
      return;
    }

    try {
      const userId = socket.data.userId;
      const [result] = await pool.query(
        "INSERT INTO rooms (name, max_users, created_by_user_id) VALUES (?, ?, ?)",
        [trimmed, 5, userId]
      );

      const room = {
        id: result.insertId,
        name: trimmed,
        maxUsers: 5,
        currentUsers: 0,
      };

      socket.emit("room:create-result", { ok: true, room });
      io.emit("room:created", room);
    } catch (err) {
      console.error("room:create 에러:", err);
      socket.emit("room:create-result", {
        ok: false,
        message: "방 생성 중 오류가 발생했습니다.",
      });
    }
  });

  socket.on("room:list", async () => {
    try {
      const [rows] = await pool.query(
        "SELECT id, name, max_users FROM rooms ORDER BY id DESC"
      );

      const list = rows.map((r) => {
        const key = String(r.id);
        const room = io.sockets.adapter.rooms.get(key);
        const current = room ? room.size : 0;
        return {
          id: r.id,
          name: r.name,
          maxUsers: r.max_users,
          currentUsers: current,
        };
      });

      socket.emit("room:list-result", list);
    } catch (err) {
      console.error("room:list 에러:", err);
      socket.emit("room:list-result", []);
    }
  });

  socket.on("chat:join", async ({ roomId }) => {
    if (!roomId) return;

    try {
      const [rows] = await pool.query(
        "SELECT id, name, max_users FROM rooms WHERE id = ?",
        [roomId]
      );
      if (rows.length === 0) {
        socket.emit("room:join-result", {
          ok: false,
          message: "존재하지 않는 방입니다.",
        });
        return;
      }

      const roomRow = rows[0];
      const roomKey = String(roomRow.id);
      const room = io.sockets.adapter.rooms.get(roomKey);
      const current = room ? room.size : 0;

      if (current >= roomRow.max_users) {
        socket.emit("room:join-result", {
          ok: false,
          message: "방 인원이 가득 찼습니다. (최대 5명)",
        });
        return;
      }

      if (socket.data.roomId && socket.data.roomId !== roomRow.id) {
        socket.leave(String(socket.data.roomId));
      }

      socket.join(roomKey);
      socket.data.roomId = roomRow.id;

      const newCurrent = current + 1;

      socket.emit("room:join-result", {
        ok: true,
        roomId: roomRow.id,
        roomName: roomRow.name,
      });

      io.emit("room:user-count-changed", {
        roomId: roomRow.id,
        currentUsers: newCurrent,
      });

      console.log(
        `유저 ${socket.data.userId}가 방 ${roomRow.id} 입장 (현재 ${newCurrent}명)`
      );
    } catch (err) {
      console.error("chat:join 에러:", err);
      socket.emit("room:join-result", {
        ok: false,
        message: "방 입장 중 오류가 발생했습니다.",
      });
    }
  });

  socket.on("chat:send", async ({ roomId, message }) => {
    if (!roomId || !message) return;

    try {
      const userId = socket.data.userId;
      const nickname = socket.data.nickname || "익명";

      const user = await findUserById(userId);
      if (!user) {
        console.log("알 수 없는 유저에서 메시지 시도");
        return;
      }

      if (user.isBanned) {
        socket.emit("chat:receive", {
          nickname: "SYSTEM",
          message: "정지된 계정입니다. 채팅을 사용할 수 없습니다.",
        });
        return;
      }

      if (isUserMuted(user)) {
        let msg = "현재 채팅 제한(mute) 상태입니다.";
        if (user.muteUntil) {
          const until = user.muteUntil;
          const yyyy = until.getFullYear();
          const mm = String(until.getMonth() + 1).padStart(2, "0");
          const dd = String(until.getDate()).padStart(2, "0");
          const hh = String(until.getHours()).padStart(2, "0");
          const mi = String(until.getMinutes()).padStart(2, "0");
          msg += ` 해제 예정 시각: ${yyyy}-${mm}-${dd} ${hh}:${mi}`;
        }

        socket.emit("chat:receive", {
          nickname: "SYSTEM",
          message: msg,
        });
        return;
      }

      const { score, maskedMessage } = evaluateMessage(message);
      console.log(`방 ${roomId} / ${nickname}: "${message}" (score=${score})`);

      let abuseLogId = null;
      if (score > 0) {
        abuseLogId = await logAbuse({
          userId,
          roomId,
          original: message,
          masked: maskedMessage,
          score,
        });
      }

      const penaltyResult = await applyPenalty(user, score, abuseLogId, roomId);

      if (user.isBanned) {
        socket.emit("chat:receive", {
          nickname: "SYSTEM",
          message:
            "욕설로 인해 계정이 정지되었습니다. 채팅을 사용할 수 없습니다.",
        });
        return;
      }

      if (penaltyResult === "muted" && isUserMuted(user)) {
        let msg = "욕설로 인해 일정 시간 동안 채팅이 제한되었습니다.";
        if (user.muteUntil) {
          const until = user.muteUntil;
          const yyyy = until.getFullYear();
          const mm = String(until.getMonth() + 1).padStart(2, "0");
          const dd = String(until.getDate()).padStart(2, "0");
          const hh = String(until.getHours()).padStart(2, "0");
          const mi = String(until.getMinutes()).padStart(2, "0");
          msg += ` 해제 예정 시각: ${yyyy}-${mm}-${dd} ${hh}:${mi}`;
        }

        socket.emit("chat:receive", {
          nickname: "SYSTEM",
          message: msg,
        });
        return;
      }

      if (penaltyResult === "warn") {
        socket.emit("chat:receive", {
          nickname: "SYSTEM",
          message:
            "주의: 욕설 사용이 감지되었습니다. 계속되면 제한될 수 있습니다.",
        });
      }

      const finalMessage = score > 0 ? maskedMessage : message;

      // 1) 같은 인스턴스에 붙어 있는 유저들에게 즉시 전송
      io.to(String(roomId)).emit("chat:receive", {
        nickname,
        message: finalMessage,
        userId: user.id,
        messageId: null,
      });

      // DynamoDB에 전체 채팅 저장 (원본 + 마스킹 + 점수)
      saveChatToDynamo({
        roomId,
        userId: user.id,
        nickname,
        original: message,
        masked: finalMessage,
        score,
        instanceId: INSTANCE_ID,
      }).catch((err) => {
        console.error("saveChatToDynamo 에러:", err);
      });

      // 2) SNS로 브로드캐스트 → SNS가 모든 SQS로 fan-out → 각 인스턴스 poller가 받아서 emit
      if (CHAT_SNS_TOPIC_ARN) {
        const broadcastPayload = {
          type: "chat",
          roomId: Number(roomId),
          message: finalMessage,
          nickname,
          userId: user.id,
          originInstanceId: INSTANCE_ID,
          sentAt: new Date().toISOString(),
        };

        // fire-and-forget; 실패해도 채팅 자체는 로컬에서는 동작
        sns
          .send(
            new PublishCommand({
              TopicArn: CHAT_SNS_TOPIC_ARN,
              Message: JSON.stringify(broadcastPayload),
            })
          )
          .catch((err) => {
            console.error("채팅 SNS 브로드캐스트 실패:", err);
          });
      } else {
        // SNS 미설정이면 인스턴스 간 동기화는 안 되지만,
        // 단일 인스턴스에서는 정상 동작
        // 필요하다면 여기 로그만 남김
        // console.log("[WARN] CHAT_SNS_TOPIC_ARN 미설정 - cross-instance 브로드캐스트 비활성화");
      }
    } catch (err) {
      console.error("chat:send 처리 중 에러", err);
      socket.emit("chat:receive", {
        nickname: "SYSTEM",
        message: "메시지 처리 중 오류가 발생했습니다.",
      });
    }
  });

  socket.on("disconnect", () => {
    console.log("클라이언트 연결 종료:", socket.id);

    const roomId = socket.data.roomId;
    if (roomId) {
      const roomKey = String(roomId);
      const room = io.sockets.adapter.rooms.get(roomKey);
      const current = room ? room.size : 0;

      io.emit("room:user-count-changed", {
        roomId,
        currentUsers: current,
      });
    }
  });
});

console.log("[BOOT] Using DynamoDB table:", CHAT_TABLE, "region:", DDB_REGION);

// ---------------- 서버 시작 + Poller 시작 ----------------
const PORT = process.env.PORT || 3000;

startChatPoller();

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
