// db.js
const mysql = require("mysql2/promise");

// const {
//   DB_HOST = "localhost",
//   DB_PORT = "3306",
//   DB_USER = "root",
//   DB_PASSWORD = "mybatis",
//   DB_NAME = "chat_filter",
// } = process.env;

// RDS 접속 정보 하드코딩 (지금 환경에서는 이게 제일 단순)
const DB_HOST = "chat-mysql.crjpe7o6zkmo.us-east-1.rds.amazonaws.com";
const DB_PORT = 3306;
const DB_USER = "admin"; // RDS 만들 때 적은 마스터 유저
const DB_PASSWORD = "RDS_비밀번호_여기에"; // 실제 비번으로 바꾸기
const DB_NAME = "chat_db"; // 우리가 만든 DB 이름

const pool = mysql.createPool({
  host: DB_HOST,
  port: Number(DB_PORT),
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

module.exports = { pool };
