import random
import hashlib
from secret import SECRET
import string
import re

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def make_salt(length):
    """Function returning a random ascii sequence to be used as salt"""
    return "".join(random.choice(string.letters) for i in range(length))


def make_cookie_hash(cleartext):
    """Function returning hashed text"""
    return "%s|%s" % (cleartext,hashlib.sha256(SECRET + cleartext).hexdigest())

def make_hashed_password(cleartext,salt=None):
    """Function returning hashed password"""
    
    if not salt:
        salt = make_salt(5)
    return "%s|%s" % (salt,hashlib.sha256(salt + cleartext).hexdigest())

def verify_cookie_hash(h):
    """Function returning hashed text"""
    val = h.split('|')[0]
    if make_cookie_hash(val) == h: 
        return val
    else:
        return None


def verify_username(entered_username):
    """Function that checks username against defined regexp"""
    return USER_RE.match(entered_username)

def verify_password(entered_password):
    """Function that checks passwordagainst defined regexp"""
    return PASSWORD_RE.match(entered_password)

def verify_email(entered_email):
    """Function that checks email against defined regexp"""
    return EMAIL_RE.match(entered_email)

