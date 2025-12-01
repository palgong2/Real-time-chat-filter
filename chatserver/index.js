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
const JWT_SECRET = "dev-secret-change-later"; // 원래 쓰던 값
const AWS_REGION = "ap-northeast-2";
const DDB_CHAT_TABLE = "ChatMessages";
const INSTANCE_ID = process.env.INSTANCE_ID || "local-dev";

// DynamoDB 클라이언트
const ddbClient = new DynamoDBClient({ region: AWS_REGION });
const ddb = DynamoDBDocumentClient.from(ddbClient, {
  marshallOptions: {
    removeUndefinedValues: true,
  },
});

// 여러 인스턴스/방 상태 관리용
const activeRooms = new Set();
const lastSeenPerRoom = new Map();

// Express 앱 생성
const app = express();
app.use(express.json());

const PROFANITY_LIST = [
  { pattern: "욕1", score: 5 },
  { pattern: "욕2", score: 10 },
  { pattern: "욕3", score: 20 },
];

// 메시지 전처리 (공백/특수문자 제거 등)
function normalizeMessage(msg) {
  if (!msg) return "";
  return msg
    .toLowerCase() // 소문자
    .replace(/\s+/g, "") // 공백 제거
    .replace(/[^\w가-힣]/g, ""); // 특수문자 제거 (한글/영문/숫자만 남김)
}

// 욕설 점수 계산 + 마스킹
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

  return {
    score: totalScore,
    maskedMessage: masked,
  };
}

async function notifyBanByEmailPlaceholder(user, abuseLogId, roomId, score) {
  console.log(
    `[BAN] user_id=${user.id}, room=${roomId}, abuse_log_id=${abuseLogId}, score=${score}`
  );
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

// DB에서 유저 조회
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

// 벌점 적용 규칙 (원하는 대로 조정 가능)
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

  // ★ 정지된 경우 ban_events에 한 줄 남기기
  if (result === "banned") {
    await pool.query(
      "INSERT INTO ban_events (user_id, abuse_log_id, room_id, score) VALUES (?, ?, ?, ?)",
      [user.id, abuseLogId, roomId, score]
    );

    await notifyBanByEmailPlaceholder(user, abuseLogId, roomId, score);
  }

  return result;
}

// mute 상태인지 확인
function isUserMuted(user) {
  if (!user || !user.muteUntil) return false;
  return user.muteUntil > new Date();
}

// public 폴더를 정적 파일로 서빙
app.use(express.static(path.join(__dirname, "public")));

// 헬스 체크용 엔드포인트
app.get("/health", (req, res) => {
  res.send("ok");
});

// 어떤 인스턴스인지 확인용
app.get("/whoami", (req, res) => {
  res.json({
    instanceId: INSTANCE_ID,
  });
});

// 회원가입
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

// 로그인
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
    });
  } catch (err) {
    console.error("로그인 에러:", err);
    return res.status(500).json({ message: "서버 에러" });
  }
});

// HTTP 서버 + Socket.IO 붙이기
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

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

io.on("connection", (socket) => {
  console.log(
    "새 클라이언트 연결됨:",
    socket.id,
    "userId:",
    socket.data.userId
  );

  function startChatPoller() {
    const POLL_INTERVAL_MS = 1000; // 1초마다 폴링

    setInterval(async () => {
      // activeRooms가 비어 있으면 할 일이 없음
      if (activeRooms.size === 0) {
        return;
      }

      for (const roomId of activeRooms) {
        try {
          const numericRoomId = Number(roomId);
          if (!numericRoomId || Number.isNaN(numericRoomId)) continue;

          const lastSeen = lastSeenPerRoom.get(numericRoomId) || null;

          let params;
          if (lastSeen) {
            // 마지막으로 본 messageId 이후의 것만 조회
            params = {
              TableName: DDB_CHAT_TABLE,
              KeyConditionExpression:
                "roomId = :roomId AND messageId > :lastMessageId",
              ExpressionAttributeValues: {
                ":roomId": numericRoomId,
                ":lastMessageId": lastSeen,
              },
              ScanIndexForward: true, // 오래된 것 → 최신 순
              Limit: 50,
            };
          } else {
            // 처음 시작하는 방이면, 일단 최근 N개만 읽고 "포인터만 맞추고" 넘어감
            params = {
              TableName: DDB_CHAT_TABLE,
              KeyConditionExpression: "roomId = :roomId",
              ExpressionAttributeValues: {
                ":roomId": numericRoomId,
              },
              ScanIndexForward: false, // 최신 것부터
              Limit: 20,
            };
          }

          const result = await ddb.send(new QueryCommand(params));
          const items = result.Items || [];

          if (items.length === 0) {
            continue;
          }

          // 정렬 방향에 따라 순서 정리
          let ordered;
          if (!lastSeen) {
            // 처음 읽을 때는 최신 → 오래된 순으로 왔으니, 뒤집어서 오래된 → 최신으로 맞춰둠
            ordered = items.slice().reverse();
            // 처음 한 번은 "예전 메시지들은 재전송하지 않고" 포인터만 세팅
            const lastItem = ordered[ordered.length - 1];
            if (lastItem && lastItem.messageId) {
              lastSeenPerRoom.set(numericRoomId, lastItem.messageId);
            }
            continue; // 브로드캐스트는 하지 않음 (중복 방지)
          } else {
            // 이미 lastSeen이 있는 경우에는 오래된 → 최신 순으로 오도록 Query했으니 그대로 사용
            ordered = items;
          }

          // 새로운 메시지들에 대해 브로드캐스트
          let latestMessageId = lastSeen;
          for (const item of ordered) {
            if (!item || !item.messageId) continue;

            // 이 메시지가 현재 인스턴스에서 생성된 거면 스킵
            if (item.originInstanceId === INSTANCE_ID) {
              latestMessageId = item.messageId;
              continue;
            }

            const payload = {
              nickname: item.nickname || "익명",
              message: item.body || "",
              userId: item.senderUserId || null,
              // messageId를 굳이 넘기고 싶으면 넘기고, 아니면 생략해도 됨
            };

            io.to(String(numericRoomId)).emit("chat:receive", payload);

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

      // 최종 전송 메시지 (욕설이면 마스킹된 버전)
      const finalMessage = score > 0 ? maskedMessage : message;

      // 1) createdAt, ddbMessageId 먼저 생성 (MySQL 없이 시간+유저ID 조합)
      const createdAt = new Date().toISOString();
      const ddbMessageId = `${createdAt}#${user.id}`;

      // 2) DynamoDB에만 저장
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
        console.error("ChatMessages(DynamoDB) 저장 실패:", err);
        // 데모 단계에서는 실패해도 채팅 브로드캐스트는 계속
      }

      // 3) 브로드캐스트 (클라이언트 messageId는 DynamoDB 키 사용)
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
      io.emit("room:user-count-changed", {
        roomId,
        currentUsers: current,
      });
    }
  });
});

// 서버 시작
const PORT = 3000;

// 폴링 루프 시작
// startChatPoller();

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
