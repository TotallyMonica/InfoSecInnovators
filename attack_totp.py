from datetime import datetime
import totp_tester
import database_handler

if __name__ == '__main__':
    # Get TOTP key, simulates socket connection to remote server
    totp = totp_tester.TotpProcessor(database_handler.UsersDB().get_mfa_key(database_handler.UsersDB().lookup_uid("passwordchecker")))

    # Get brute force start time
    start_time = datetime.now()
    stop_time = start_time
    code = ""

    # Loop to brute force keys
    for i in range(999999):
        code = f"{i:06d}"
        valid = totp.validate(code)
        if valid:
            stop_time = datetime.now()
            break

    if start_time == stop_time:
        print("Could not brute force TOTP validation")
    else:
        print(f"Found code {code} in {stop_time - start_time}")
