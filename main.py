#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Google App Engine app"""
import os 
import webapp2
import jinja2
import re
import cgi
import hashlib
import random
import string
import logging
from secret import SECRET

from google.appengine.ext import db



jinja_env = jinja2.Environment(
        autoescape=True, loader = jinja2.FileSystemLoader(
            os.path.join(os.path.dirname(__file__), 'templates')))

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

#General 
def render_str(template, **params):
    """Function that render a jinja template with string substitution"""
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
    """General class to render http response"""


    def write(self, *a, **kw):
        """Write generic http response with the passed parameters"""
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """Utility function that can add new stuff to parameters passed"""
        if self.user : 
          params['welcome']='%s' % self.user.username
          params['logout']='Logout'
        else :
          params['welcome']='Login'
          params['login']='Login'
          params['signup']='Signup'

        return render_str(template, **params)

    def render(self, template, **kw):         
        """Render jinja template with named parameters"""
        self.write(self.render_str(template, **kw))
    
    def set_secure_cookie(self, name, val):
        """Send a http header with a hashed cookie"""
        hashed_cookie = make_cookie_hash(val)
        self.response.headers.add_header('Set-Cookie',
              "%s=%s; Path='/'" % (name,hashed_cookie))

    def read_secure_cookie(self, name):
        """Check if requesting browser sent us a cookie"""
        hashed_cookie = self.request.cookies.get(name)
        if hashed_cookie :
            return verify_cookie_hash(hashed_cookie)
        else:
            return None

    def initialize(self, *a, **kw):
        """Function called before requests are processed.
           Used to check for sent cookies"""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))

#signup part

class User(db.Model):
    """Model class representing user data"""

    username = db.StringProperty(required = True)
    hashed_pwd = db.StringProperty(required = True)
    email = db.StringProperty(required = False)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

class SignupHandler(Handler):
    """Class for handling signup form interaction"""

    def show_form(self, 
            error_username, 
            error_password, 
            error_email, 
            last_username, 
            last_email):
        """Utility function to render the signup form"""

        self.render("signup.html", 
                error_username=error_username, 
                error_password=error_password, 
                error_email=error_email, 
                last_username=last_username, 
                last_email=last_email)

    def get(self):
        """Function called unpon loading signup page"""
        self.show_form("", "", "", "", "")

    def verify_username(self, entered_username):
        """Function that checks username against defined regexp"""
        return USER_RE.match(entered_username)

    def verify_password(self, entered_password):
        """Function that checks passwordagainst defined regexp"""
        return PASSWORD_RE.match(entered_password)

    def verify_email(self, entered_email):
        """Function that checks email against defined regexp"""
        return EMAIL_RE.match(entered_email)

    def post(self):
        """Function that gets called when form is submitted"""
        error_username = ""
        error_password = ""
        error_email = ""

        entered_username = cgi.escape(self.request.get("username"))

        if cgi.escape(self.request.get("username")) == "" :
            error_username = "Please enter username" 
        elif self.verify_username(entered_username) == None:
            error_username = "Username not valid" 
        else :
            query= db.GqlQuery("select * from User where username = :1",
                    entered_username) 
            if query.get():
                error_username = "Username already exists"

        entered_password =  cgi.escape(self.request.get("password"))
        entered_verify = cgi.escape(self.request.get("verify"))

        if entered_password == "":
            error_password = "Please enter password" 
        elif entered_verify == "":
            error_password = "Please enter a matching password" 
        elif self.verify_password(entered_password) == None:
            error_password = "Password not valid" 
        elif entered_password != entered_verify :
            error_password = "Passwords do not match" 


        entered_email = cgi.escape(self.request.get("email"))
        if entered_email and self.verify_email(entered_email) == None:
            error_email = "Email not valid" 

        if (error_username != "" or error_password !="" or error_email!=""):
            self.show_form(error_username, 
                    error_password, 
                    error_email, 
                    entered_username,
                    entered_email)
        else:
            new_user = User(username=entered_username,
                            hashed_pwd=make_hashed_password(entered_password), 
                            email=entered_email)
            new_user.put()
            self.set_secure_cookie('user_id',str(new_user.key().id()))
            self.redirect("/profile")

class WelcomeHandler(Handler):
    """Class used to display the welcome (successful signup) page"""

    def get(self):
        """Function called when the page is requested"""

        user_cookie = self.request.cookies.get("user", "")
        if user_cookie and verify_cookie_hash(user_cookie):
            self.render("welcome.html", username=user_cookie.split('|')[0])
        else:
            self.redirect("/signup")

class ProfileHandler(Handler):
    """Class for handling User profile page"""

    def get(self):
        """Function called upon loading login page"""
        user_cookie = self.request.cookies.get("user_id", "")
        if user_cookie and verify_cookie_hash(user_cookie):
            self.render("profile.html")
        else :
            self.redirect("/login")




#login
class LoginHandler(Handler):
    """Class for handling login form interaction"""

    def show_form(self, 
            error, 
            last_username):
        """Utility function to render the login form"""

        self.render("login.html", 
                error=error, 
                last_username=last_username)

    def get(self):
        """Function called upon loading login page"""
        self.show_form("", "")


    def post(self):
        """Function that gets called when form is submitted"""      
        error = ""
        error_email = ""

        entered_username = cgi.escape(self.request.get("username"))
        entered_password =  cgi.escape(self.request.get("password"))

        if not entered_username or not entered_password:
            error = "Please enter Username and password"
            self.show_form(error, 
                    entered_username)
            return
            

        query = db.GqlQuery("select * from User where username = :1",
                entered_username) 

        user = query.get()
        if  user :
            stored_hash = user.hashed_pwd
            generated_hash = make_hashed_password(entered_password,
                    stored_hash.split('|')[0]) 
            if stored_hash != generated_hash :
                error = "Username or password not valid"
        else:
                error = "Username or password not valid"


        if (error):
            self.show_form(error, 
                    entered_username)
        else:
            self.set_secure_cookie('user_id',str(user.key().id()))
            self.redirect("/profile")

#login
class LogoutHandler(Handler):
    """Class for handling login form interaction"""

    def get(self):
        """Function called upon loading login page"""
        self.set_secure_cookie("user_id","")
        self.redirect("/")




class FrontPageHandler(Handler):
    """Class used to render the main page of the site"""

    def render_front(self, entries={}):
        """utility function used to render the front page"""
        self.render('index.html')

    def get(self):
        """Function called when the front page is requested"""
        self.render_front()



app = webapp2.WSGIApplication([
    ('/', FrontPageHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/signup', SignupHandler),
    ('/profile', ProfileHandler)],
    debug=True)
