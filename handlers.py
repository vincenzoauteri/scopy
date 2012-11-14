import os 
from google.appengine.ext import db
from users import User
import webapp2
import re
import cgi
from security import *
import jinja2

jinja_env = jinja2.Environment(
        autoescape=True, loader = jinja2.FileSystemLoader(
            os.path.join(os.path.dirname(__file__), 'templates')))

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

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
