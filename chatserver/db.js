// db.js
const mysql = require("mysql2/promise");

const pool = mysql.createPool({
  host: "localhost",
  user: "root", // 본인 MySQL 계정
  password: "mybatis", // 본인 비밀번호
  database: "chat_filter",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

module.exports = { pool };
