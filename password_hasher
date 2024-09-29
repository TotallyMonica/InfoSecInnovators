import bcrypt

def hashing_password(password):
    # Generate salt
    salt = bcrypt.gensalt()
    
    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    
    return hashed_password

def save_to_file(hashed_password, filename='hashed_password.txt'):
    """Saves the hashed password to a file."""
    with open(filename, 'wb') as f:
        f.write(hashed_password)
