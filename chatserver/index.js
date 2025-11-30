const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { pool } = require("./db");

const JWT_SECRET = "dev-secret-change-later"; // 나중에 env로 뺄 예정

const app = express();

// JSON Body 파싱 미들웨어
app.use(express.json());

// 구조: { id, email, passwordHash, nickname, isBanned, penaltyPoints, muteUntil }

// 아주 단순한 욕설 사전 (테스트용)
// pattern 에는 실제 욕 단어를 넣으시면 됩니다.
const PROFANITY_LIST = [
  { pattern: "욕1", score: 5 },
  { pattern: "욕2", score: 10 },
  { pattern: "욕3", score: 20 },
];

// 메시지 전처리 (너무 복잡하게 안 가고, 최소한만)
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

  // 마스킹용: 원본 문자열 기준으로 동작
  let masked = original;

  for (const item of PROFANITY_LIST) {
    const word = item.pattern;
    const score = item.score;

    if (!word) continue;

    // 정규화된 문자열에 포함돼 있으면 점수 추가
    if (normalized.includes(word)) {
      totalScore += score;

      // 원본 문자열에서 해당 단어를 ***로 치환 (단순 버전)
      const re = new RegExp(word, "gi"); // 대소문자 무시
      masked = masked.replace(re, "***");
    }
  }

  return {
    score: totalScore,
    maskedMessage: masked,
  };
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
async function applyPenalty(user, score) {
  if (!user || score <= 0) return null;

  let newPenaltyPoints = (user.penaltyPoints ?? 0) + score;
  let newIsBanned = !!user.isBanned;
  let newMuteUntil = user.muteUntil ? new Date(user.muteUntil) : null;
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
      "SELECT id, email, password_hash, nickname, is_banned, penalty_points, mute_until FROM users WHERE email = ?",
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

  socket.on("chat:join", ({ roomId }) => {
    if (!roomId) return;
    socket.join(roomId);
    console.log(`유저 ${socket.data.userId} 이(가) 방 ${roomId} 에 입장`);
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
        socket.emit("chat:receive", {
          nickname: "SYSTEM",
          message: "현재 채팅 제한(mute) 상태입니다.",
        });
        return;
      }

      const { score, maskedMessage } = evaluateMessage(message);
      console.log(`방 ${roomId} / ${nickname}: "${message}" (score=${score})`);

      const penaltyResult = await applyPenalty(user, score);

      if (user.isBanned) {
        socket.emit("chat:receive", {
          nickname: "SYSTEM",
          message:
            "욕설로 인해 계정이 정지되었습니다. 채팅을 사용할 수 없습니다.",
        });
        return;
      }

      if (isUserMuted(user)) {
        socket.emit("chat:receive", {
          nickname: "SYSTEM",
          message: "욕설로 인해 일정 시간 동안 채팅이 제한되었습니다.",
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

      io.to(roomId).emit("chat:receive", {
        nickname,
        message: finalMessage,
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
  });
});

// 서버 시작
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
