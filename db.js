const { Client } = require("pg");
const bcrypt = require("bcrypt");

let DB_URI;

DB_URI = "postgresql:///jobly";

let db = new Client({
  connectionString: DB_URI
});

db.connect();

db.query(`CREATE TABLE IF NOT EXISTS users(
  username text,
  password text,
  email text,
  name text,
  isAdmin bool
)`);

async function makeAdmin() {
  const admin = await db.query(`SELECT * FROM users WHERE username='admin' AND isAdmin=true`);
  if(admin.rows.length==0)
    db.query(`INSERT INTO users VALUES('admin', $1, 'principal@domain.suffix', 'John Doe', true)`,
    [await bcrypt.hash('smellyPassword', 12)])
}

makeAdmin();

db.query(`CREATE TABLE IF NOT EXISTS jobs(
    id int,
    title text,
    company text,
    description text,
    salary float,
    equity float,
    posterUsername text
)`);

module.exports = db;