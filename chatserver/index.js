// index.js
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { pool } = require("./db");

const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const {
  DynamoDBDocumentClient,
  PutCommand,
  QueryCommand,
} = require("@aws-sdk/lib-dynamodb");

// ===== 기본 설정들 =====
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-later";
const AWS_REGION = process.env.AWS_REGION || "ap-northeast-2";
const DDB_CHAT_TABLE = process.env.DDB_CHAT_TABLE || "ChatMessages";
const INSTANCE_ID = process.env.INSTANCE_ID || "local-dev";

// DynamoDB 클라이언트
const ddbClient = new DynamoDBClient({ region: AWS_REGION });
const ddb = DynamoDBDocumentClient.from(ddbClient, {
  marshallOptions: { removeUndefinedValues: true },
});

// 여러 인스턴스/방 상태 관리용
const activeRooms = new Set(); // 이 인스턴스에서 사용 중인 roomId 목록
const lastSeenPerRoom = new Map(); // roomId -> 마지막으로 본 messageId

// Express 앱 생성
const app = express();
app.use(express.json());

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

// ---------------- RDS 쪽 유저/제재 로직 ----------------
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

async function notifyBanByEmailPlaceholder(user, abuseLogId, roomId, score) {
  const logs = await getRecentAbuseLogs(user.id, 5);

  // TODO: 여기서 logs를 문자열로 예쁘게 포맷해서
  // AWS SNS(또는 SES)로 user.email에 전송하는 코드 넣을 예정
  console.log("=== BAN NOTIFY START ===");
  console.log("정지 대상 이메일:", user.email);
  console.log("최근 욕설 로그 예시:", logs);
  console.log("=== BAN NOTIFY END ===");
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
    await pool.query(
      "INSERT INTO ban_events (user_id, abuse_log_id, room_id, score) VALUES (?, ?, ?, ?)",
      [user.id, abuseLogId, roomId, score]
    );

    await notifyBanByEmailPlaceholder(user, abuseLogId, roomId, score);
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

// ---------------- DynamoDB Poller ----------------
function startChatPoller() {
  const POLL_INTERVAL_MS = 1000;

  setInterval(async () => {
    if (activeRooms.size === 0) return;

    for (const roomId of activeRooms) {
      try {
        const numericRoomId = Number(roomId);
        if (!numericRoomId || Number.isNaN(numericRoomId)) continue;

        const lastSeen = lastSeenPerRoom.get(numericRoomId) || null;

        let params;
        if (lastSeen) {
          params = {
            TableName: DDB_CHAT_TABLE,
            KeyConditionExpression:
              "roomId = :roomId AND messageId > :lastMessageId",
            ExpressionAttributeValues: {
              ":roomId": numericRoomId,
              ":lastMessageId": lastSeen,
            },
            ScanIndexForward: true, // 오래된 → 최신
            Limit: 50,
          };
        } else {
          params = {
            TableName: DDB_CHAT_TABLE,
            KeyConditionExpression: "roomId = :roomId",
            ExpressionAttributeValues: {
              ":roomId": numericRoomId,
            },
            ScanIndexForward: false, // 최신부터
            Limit: 20,
          };
        }

        const result = await ddb.send(new QueryCommand(params));
        const items = result.Items || [];
        if (items.length === 0) continue;

        let ordered;
        if (!lastSeen) {
          ordered = items.slice().reverse(); // 오래된 → 최신
          const lastItem = ordered[ordered.length - 1];
          if (lastItem && lastItem.messageId) {
            lastSeenPerRoom.set(numericRoomId, lastItem.messageId);
          }
          // 첫 로드는 과거 메시지 재전송 X
          continue;
        } else {
          ordered = items; // 이미 오래된 → 최신 순
        }

        let latestMessageId = lastSeen;
        for (const item of ordered) {
          if (!item || !item.messageId) continue;

          if (item.originInstanceId === INSTANCE_ID) {
            latestMessageId = item.messageId;
            continue;
          }

          io.to(String(numericRoomId)).emit("chat:receive", {
            nickname: item.nickname || "익명",
            message: item.body || "",
            userId: item.senderUserId || null,
            messageId: item.messageId,
          });

          latestMessageId = item.messageId;
        }

        if (latestMessageId && latestMessageId !== lastSeen) {
          lastSeenPerRoom.set(numericRoomId, latestMessageId);
        }
      } catch (err) {
        console.error("chat poller 에러 (roomId=" + roomId + "):", err);
      }
    }
  }, POLL_INTERVAL_MS);
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

      // 이 방을 Poller 대상에 추가
      activeRooms.add(roomRow.id);

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

      const createdAt = new Date().toISOString();
      const ddbMessageId = `${createdAt}#${user.id}`;

      // 🔹 DynamoDB에 채팅 저장
      try {
        await ddb.send(
          new PutCommand({
            TableName: DDB_CHAT_TABLE,
            Item: {
              roomId: Number(roomId),
              messageId: ddbMessageId,
              senderUserId: Number(user.id),
              nickname: nickname,
              body: finalMessage,
              originalMessage: message,
              score: Number(score),
              createdAt: createdAt,
              originInstanceId: INSTANCE_ID,
            },
          })
        );
      } catch (err) {
        console.error("DynamoDB ChatMessages 저장 실패:", err);
      }

      // 🔹 같은 인스턴스의 유저들에게 즉시 전송
      io.to(String(roomId)).emit("chat:receive", {
        nickname,
        message: finalMessage,
        userId: user.id,
        messageId: ddbMessageId,
      });
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

      // 방에 아무도 없으면 Poller 대상에서 제거
      if (!room || room.size === 0) {
        activeRooms.delete(roomId);
        lastSeenPerRoom.delete(Number(roomId));
      }

      io.emit("room:user-count-changed", {
        roomId,
        currentUsers: current,
      });
    }
  });
});

// ---------------- 서버 시작 + Poller 시작 ----------------
const PORT = process.env.PORT || 3000;

startChatPoller();

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
