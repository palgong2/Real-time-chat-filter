const express = require("express");
const http = require("http");
const path = require("path");
const { Server } = require("socket.io");

const app = express();

// JSON Body 파싱 미들웨어
app.use(express.json());

// 아주 간단한 메모리 유저 저장소 (나중에 DB로 바꿀 예정)
let nextUserId = 1;
const users = [];
// 구조: { id, email, password, nickname, isBanned, penaltyPoints, muteUntil }

// public 폴더를 정적 파일로 서빙
app.use(express.static(path.join(__dirname, "public")));

// 헬스 체크용 엔드포인트
app.get("/health", (req, res) => {
  res.send("ok");
});

// 회원가입
app.post("/auth/register", (req, res) => {
  const { email, password, nickname } = req.body;

  // 1) 기본 값 체크
  if (!email || !password || !nickname) {
    return res
      .status(400)
      .json({ message: "email, password, nickname 은 필수입니다." });
  }

  // 2) 중복 이메일 체크
  const existing = users.find((u) => u.email === email);
  if (existing) {
    return res.status(409).json({ message: "이미 사용 중인 이메일입니다." });
  }

  // 3) 유저 생성 (지금은 비밀번호를 그대로 저장, 나중에 bcrypt로 암호화 예정)
  const newUser = {
    id: nextUserId++,
    email,
    password, // 나중에 passwordHash 로 변경
    nickname,
    isBanned: false,
    penaltyPoints: 0,
    muteUntil: null, // 나중에 Date 객체/문자열로 사용
  };
  users.push(newUser);

  return res.status(201).json({
    message: "회원가입 성공",
    userId: newUser.id,
    nickname: newUser.nickname,
  });
});

// 로그인
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;

  // 1) 기본 값 체크
  if (!email || !password) {
    return res.status(400).json({ message: "email, password 는 필수입니다." });
  }

  // 2) 유저 찾기
  const user = users.find((u) => u.email === email);
  if (!user) {
    return res
      .status(401)
      .json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." });
  }

  // 3) 비밀번호 확인 (지금은 단순 비교, 나중에 bcrypt.compare로 변경)
  if (user.password !== password) {
    return res
      .status(401)
      .json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." });
  }

  // 4) 정지된 계정인지 체크
  if (user.isBanned) {
    return res
      .status(403)
      .json({ message: "정지된 계정입니다. 로그인할 수 없습니다." });
  }

  // 5) 로그인 성공 응답
  //    지금은 단순히 유저 정보만 반환. 나중에 JWT 토큰으로 교체.
  return res.json({
    message: "로그인 성공",
    userId: user.id,
    nickname: user.nickname,
  });
});

// HTTP 서버 + Socket.IO 붙이기
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

// 기본 채팅 룸 입장/메시지 브로드캐스트
io.on("connection", (socket) => {
  console.log("새 클라이언트 연결됨:", socket.id);

  socket.on("chat:join", ({ roomId }) => {
    if (!roomId) return;
    socket.join(roomId);
    console.log(`소켓 ${socket.id} 이(가) 방 ${roomId} 에 입장`);
  });

  socket.on("chat:send", ({ roomId, nickname, message }) => {
    if (!roomId || !message) return;

    const safeNickname = nickname || "익명";
    console.log(`방 ${roomId} / ${safeNickname}: ${message}`);

    io.to(roomId).emit("chat:receive", {
      nickname: safeNickname,
      message,
    });
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
