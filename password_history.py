# AUTHOR: Monica Hanson
# DATE: 9/16/2024

import hashlib
import os
import sqlite3
import string

con = sqlite3.connect('passwords.db')
cur = con.cursor()

def init_db():
    cur.execute(
        "CREATE TABLE IF NOT EXISTS passwords (pid INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER, password TEXT)")
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users (uid INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password INTEGER)")
    con.commit()

def retrieve_password_history(uid: int, row_count: int = 0) -> list[str]:
    query = "SELECT password FROM passwords WHERE uid=?"
    params = (uid,)
    if row_count > 0:
        query += " ORDER BY pid DESC LIMIT ?"
        params = (uid, row_count)
    cur.execute(query, params)
    results = cur.fetchall()
    return results

def update_password(uid: int, password: str) -> bool:
    if not check_if_password_exists(uid, password, 3):
        cur.execute("INSERT INTO passwords (uid, password) VALUES (?, ?)", (uid, password))
        con.commit()
        cur.execute("SELECT pid FROM passwords WHERE uid=? AND password=?", (uid, password))
        pid = cur.fetchall()[0][0]
        cur.execute("UPDATE users SET password=? WHERE uid=?", (pid, uid))
        con.commit()
        return True
    return False


def check_if_password_exists(uid: int, password: str, use_count: int = 0) -> bool:
    history = retrieve_password_history(uid, use_count)
    for row in history:
        if password == row[0]:
            return True
    return False

def hash_password(password: str) -> string:
    hasher = hashlib.sha3_512(f"{password}:InfoSecInnovatorsSalt".encode('utf-8'))
    return hasher.hexdigest()

def lookup_uid(username: str) -> int:
    cur.execute("SELECT uid FROM users WHERE username=?", (username,))
    return cur.fetchall()[0][0]

def insert_new_user(username: str, password: str):
    cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    con.commit()
    uid = lookup_uid(username)
    cur.execute("INSERT INTO passwords (uid, password) VALUES (?, ?)", (uid, password))
    con.commit()
    update_password(uid, password)

init_db()

def main():
    username = input("Enter username: ")
    password = input("Enter Password: ")
    insert_new_user(username, hash_password(password))
    while True:
        username = input("Enter username: ")
        password = input("Enter Password: ")
        if username == "" and password == "":
            os.exit(0)
        uid = lookup_uid(username)
        if update_password(uid, hash_password(password)):
            print("Password updated!")
        else:
            print("Password has been used before. Use a different one.")

if __name__ == '__main__':
    main()
