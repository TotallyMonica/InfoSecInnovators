import sqlite3

class UsersDB:
    def __init__(self):
        self.con = sqlite3.connect('passwords.db')
        self.cur = self.con.cursor()
        self.init_db()

    def init_db(self):
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS passwords (pid INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER, password TEXT)")
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS users (uid INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password INTEGER, mfa TEXT)")
        self.con.commit()

    def retrieve_password_history(self, uid: int, row_count: int = 0) -> list[str]:
        query = "SELECT password FROM passwords WHERE uid=?"
        params = (uid,)
        if row_count > 0:
            query += " ORDER BY pid DESC LIMIT ?"
            params = (uid, row_count)
        self.cur.execute(query, params)
        return self.cur.fetchall()

    def update_password(self, uid: int, password: str):
        self.cur.execute("INSERT INTO passwords (uid, password) VALUES (?, ?)", (uid, password))
        self.con.commit()
        self.cur.execute("SELECT pid FROM passwords WHERE uid=? AND password=?", (uid, password))
        pid = self.cur.fetchall()[0][0]
        self.cur.execute("UPDATE users SET password=? WHERE uid=?", (pid, uid))
        self.con.commit()

    def lookup_uid(self, username: str) -> int:
        self.cur.execute("SELECT uid FROM users WHERE username=?", (username,))
        return self.cur.fetchall()[0][0]

    def insert_new_user(self, username: str, password: str):
        self.cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        self.con.commit()
        uid = self.lookup_uid(username)
        self.cur.execute("INSERT INTO passwords (uid, password) VALUES (?, ?)", (uid, password))
        self.con.commit()
        self.update_password(uid, password)

    def get_mfa_key(self, uid: int) -> str:
        self.cur.execute("SELECT mfa FROM users WHERE uid=?", (uid,))
        mfa = self.cur.fetchall()[0][0]
        return mfa

    def insert_mfa_key(self, uid: int, key: str):
        self.cur.execute("UPDATE users SET mfa =? WHERE uid=?", (key, uid))
        self.con.commit()