import secrets
import bcrypt
from datetime import datetime, timedelta, timezone


def generate_otp():

    return f"{secrets.randbelow(1000000):06d}"


def hash_otp(otp):

    return bcrypt.hashpw(
        otp.encode(),
        bcrypt.gensalt()
    ).decode()


def verify_otp(otp, hashed):

    return bcrypt.checkpw(
        otp.encode(),
        hashed.encode()
    )


def get_expiry():

    return datetime.now(timezone.utc) + timedelta(minutes=5)