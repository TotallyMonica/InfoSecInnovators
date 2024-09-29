# AUTHOR: Monica Hanson
# DATE: 9/16/2024

import hashlib
import os
import string
import database_handler

users_db = database_handler.UsersDB()

def update_password(uid: int, password: str) -> bool:
    if not check_if_password_exists(uid, password, 3):
        users_db.update_password(uid, password)
        return True
    return False

def check_if_password_exists(uid: int, password: str, use_count: int = 0) -> bool:
    history = users_db.retrieve_password_history(uid, use_count)
    for row in history:
        if password == row[0]:
            return True
    return False

def hash_password(password: str) -> string:
    hasher = hashlib.sha3_512(f"{password}:InfoSecInnovatorsSalt".encode('utf-8'))
    return hasher.hexdigest()

def main():
    username = input("Enter username: ")
    password = input("Enter Password: ")
    users_db.insert_new_user(username, hash_password(password))
    while True:
        username = input("Enter username: ")
        password = input("Enter Password: ")
        if username == "" and password == "":
            os.exit(0)
        uid = users_db.lookup_uid(username)
        if update_password(uid, hash_password(password)):
            print("Password updated!")
        else:
            print("Password has been used before. Use a different one.")

if __name__ == '__main__':
    main()
