from google.appengine.ext import db

class User(db.Model):
    """Model class representing user data"""

    username = db.StringProperty(required = True)
    hashed_pwd = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
