const db = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { SECRET_KEY, authenticateToken } = require("./auth");
const express = require("express");
const cors = require("cors");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

db.connect((err, client, release) => {
  if (err) {
    return console.error("Error!", err.stack);
  }

  console.log("Database connected!");
  release();
});

app.get("/", (req, res) => {
  res.send("Hello, World");
});

app.get("/users", authenticateToken, async (req, res) => {
  const { user } = req;

  const result = await db.query("SELECT * FROM users WHERE email = $1", [
    user.email,
  ]);

  res.json(result.rows[0]);
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ error: "メールアドレスまたはパスワードが正しくありません。" });
  }

  const existingUser = await db.query("SELECT * FROM users WHERE email = $1", [
    email,
  ]);
  if (existingUser.rows.length > 0) {
    return res
      .status(409)
      .json({ error: "このメールアドレスは既に登録されています。" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [
      email,
      hashedPassword,
    ]);

    const token = jwt.sign({ email: email }, SECRET_KEY, { expiresIn: "1h" });

    res.status(201).json({ token });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ error: "アカウントの作成中にエラーが発生しました。" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const result = await db.query("SELECT * FROM users WHERE email = $1", [
    email,
  ]);

  if (result.rows.length === 0) {
    return res.status(404).json({ error: "Wrong credentials" });
  }

  const user = result.rows[0];
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ error: "Wrong credentials" });
  }

  const token = jwt.sign({ email: email }, SECRET_KEY, { expiresIn: "1h" });

  res.json({ token });
});

app.put("/update/:email", async (req, res) => {
  const { email } = req.params;
  const { password } = req.body;

  const result = await db.query(
    "UPDATE users SET password = $2 WHERE email = $1 RETURNING *",
    [email, password]
  );
  res.send("変更完了しました");
});

app.delete("/delete", async (req, res) => {
  const { email } = req.body;

  try {
    const result = await db.query(
      "DELETE FROM users WHERE email = $1 RETURNING *",
      [email]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "ユーザーが見つかりません" });
    }

    res.status(200).json({ message: "ユーザーが削除されました" });
  } catch (error) {
    console.error("削除中にエラーが発生しました:", error);
    res.status(500).json({ message: "内部サーバーエラー" });
  }
});

app.listen(PORT, () => {
  console.log(`サーバー${PORT}を起動しました`);
});
