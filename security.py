import random
import hashlib
from secret import SECRET
import string

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
