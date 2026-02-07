import bcrypt

def hash_password(plain_password: str) -> str:
    pw_bytes = plain_password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pw_bytes, salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, stored_hash: str) -> bool:
    pw_bytes = plain_password.encode("utf-8")
    hash_bytes = stored_hash.encode("utf-8")
    return bcrypt.checkpw(pw_bytes, hash_bytes)
