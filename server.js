let express = require('express');
let cors = require('cors');
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const db = require("./db");
const { authenticateJWT, ensureLoggedIn, ensureAdmin, SECRET_KEY } = require("./middleware/auth");
const { max } = require('pg/lib/defaults');

let app = express();
app.use(express.json());
app.use(authenticateJWT);

app.use(cors());


app.post('/register', async (req, res, next) => {
    try {
      const { email, name, username, password } = req.body;
      const hashedPassword = await bcrypt.hash(
        password, 12);

      const testUsernameAvailability = await db.query(
        `SELECT * FROM users WHERE username=$1`,
        [username]
      );

      if(testUsernameAvailability.rows.length!==0)
        res.json('Username taken');

      const result = await db.query(
        `INSERT INTO users (email, name, username, password)
               VALUES ($1, $2, $3, $4)
               RETURNING username`,
        [email, name, username, hashedPassword]);
  
      return res.json(result.rows[0]);
    } catch (err) {
      return next(err);
    }
});

app.post('/login', async (req, res, next) => {
    try {
      const { username, password } = req.body;

      const result = await db.query(
        `SELECT password, isAdmin FROM users WHERE username = $1`,
        [username]);
      const user = result.rows[0];

      if (user) {
        if (await bcrypt.compare(password, user.password) === true) {
          const payload = { 'username': username, 'isAdmin': user.isadmin };
          const token = jwt.sign(payload, SECRET_KEY);
          return res.json({ token });
        }
      }
      next(req, res);
    } catch (err) {
      return next(err);
    }
});

app.post('/profile/update', ensureLoggedIn, async (req, res, next) => {
    try {
      const username = req.user.username;
      const { email, name, oldPassword, newPassword } = req.body;

      let result = await db.query(
        `SELECT password FROM users WHERE username = $1`,
        [username]);
      const user = result.rows[0];

      if (await bcrypt.compare(oldPassword, user.password) === true) {
        if(newPassword.length>0) {
            result = await db.query(
              `UPDATE users SET email=$1, name=$2, password=$3 WHERE username=$4`,
              [email, name, await bcrypt.hash(newPassword, 12), username]
            );
        } else {
          result = await db.query(
            `UPDATE users SET email=$1, name=$2 WHERE username=$3`,
            [email, name, username]
          );
        }
      } else {
        return res.json({"status": "FAILURE", "reason": "bad password"});
      }

      return res.json({"status": "SUCCESS"});
    } catch (err) {
      return next(err);
    }
});

app.post('/profile', ensureLoggedIn, async (req, res, next) => {
    try {
      const username = req.user.username;
      const result = await db.query(
        `SELECT username, name, email FROM users WHERE username=$1`,
        [username]
      );

      return res.json(result.rows[0]);
    } catch (err) {
      return next(err);
    }
});

app.post('/auth/admin', ensureAdmin, async (req, res, next) => {
  return res.send({"status": "SUCCESS"});
});

app.post('/auth', ensureLoggedIn, async (req, res, next) => {
  return res.send({"status": "SUCCESS"});
});

app.post('/joblist', ensureLoggedIn, async (req, res, next) => {
  const jobs = await db.query(
    `SELECT id, title, company, description, salary, equity FROM jobs`
  );
  return res.send(JSON.stringify(jobs.rows));
});

app.post('/jobs', ensureLoggedIn, async (req, res, next) => {
  const { title, company, description, salary, equity } = req.body;
  let id;
  try {
    id = (await db.query(`SELECT MAX(id) FROM jobs`)).rows[0].max+1;
    if(!id)
      id = 0;
  } catch(e) {
    id = 0;
  }
  const jobs = await db.query(
    `INSERT INTO jobs VALUES($1, $2, $3, $4, $5, $6, $7)`,
    [id, title, company, description, salary, equity, req.user.username]
  );
  return res.send({"status": "SUCCESS"});
});
  
app.use(function (req, res, next) {
  const notFoundError = new ExpressError("Not Found", 404);
  return next(notFoundError)
});

app.use(function(err, req, res, next) {
  let status = err.status || 500;
  let message = err.message;

  return res.status(status).json({
    error: {message, status}
  });
});

app.listen(2000, () => {} )
