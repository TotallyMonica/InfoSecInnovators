import datetime

# Set for minutes
PASSWORD_EXPIRATION = 1

# Is password expired
def check_password_expiration(last_changed_date):
    current_date = datetime.datetime.now()
    expiration_date = last_changed_date + datetime.timedelta(minutes=PASSWORD_EXPIRATION)
    
    if current_date > expiration_date:
        # Valid
        return True
    else:
        # Invalid
        return False

# Set last password change set to 0 if you want it to not be expired set higher to force expiration
def get_last_password_change():
    return datetime.datetime.now() - datetime.timedelta(minutes=0)
