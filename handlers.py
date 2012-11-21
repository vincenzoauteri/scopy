import os 
from google.appengine.ext import db
from users import User
from users import NewsletterSubscriber
import webapp2
import re
import cgi
from security import *
import jinja2
import logging
from mail import *

jinja_env = jinja2.Environment(
        autoescape=True, loader = jinja2.FileSystemLoader(
            os.path.join(os.path.dirname(__file__), 'templates')))


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
        params['style']='cerulean'
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
        logging.error("Cookie name %s hash %s" % (name,hashed_cookie)) 
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


    def post(self):
        """Function that gets called when form is submitted"""
        error_username = ""
        error_password = ""
        error_email = ""

        entered_username = cgi.escape(self.request.get("username"))

        if cgi.escape(self.request.get("username")) == "" :
            error_username = "Please enter username" 
        elif verify_username(entered_username) == None:
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
        if entered_email and verify_email(entered_email) == None:
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
            last_email):
        """Utility function to render the login form"""

        self.render("login.html", 
                error=error, 
                last_email=last_email)

    def get(self):
        """Function called upon loading login page"""
        self.show_form("", "")


    def post(self):
        """Function that gets called when form is submitted"""      
        error = ""
        error_email = ""

        entered_email= cgi.escape(self.request.get("email"))
        entered_password =  cgi.escape(self.request.get("password"))

        if not entered_email or not entered_password:
            error = "Please enter your sign-up E-mail and password"
            self.show_form(error, 
                    entered_email)
            return
            

        query = db.GqlQuery("select * from User where email = :1",
                entered_email) 

        user = query.get()
        if  user :
            stored_hash = user.hashed_pwd
            generated_hash = make_hashed_password(entered_password,
                    stored_hash.split('|')[0]) 
            if stored_hash != generated_hash :
                error = "E-mail or password not valid"
        else:
                error = "E-mail or password not valid"


        if (error):
            self.show_form(error, 
                    entered_email)
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



class AboutUsHandler(Handler):
    """Rendering for the page on about us"""

    def render_front(self, entries={}):
        self.render('about.html')

    def get(self):
        self.render_front()

class FrontPageHandler(Handler):
    """Class used to render the main page of the site"""

    def render_front(self, entries={}):
        """utility function used to render the front page"""
        self.render('index.html')

    def get(self):
        """Function called when the front page is requested"""
        self.render_front()

    def post(self):
        entered_email= cgi.escape(self.request.get("email"))
        logging.error("Entered email %s" % entered_email)
        #Check for valid address
        error=""

        if not entered_email or not verify_email(entered_email):
            error = "Please enter a valid e-mail"
        query = db.GqlQuery("select * from NewsletterSubscriber where email = :1",
                entered_email) 

        #Check if e-mail is already in database
        newsletter_subscriber = query.get()
        if  newsletter_subscriber:
            error = "You are already registered for receiving updates. Thanks for your interest!"
        else:
            new_subscriber = NewsletterSubscriber(email=entered_email)
            new_subscriber.put()

        #For the moment we disable error checking
        if False:
        #if error!="":
           self.redirect('/')
        else:
           send_email('thankyou.txt',entered_email)
           self.redirect('/thankyou')

class ThankyouHandler(Handler):
    """Class used to render the thankyou page after subscribing to the newsletter"""

    def render_front(self, entries={}):
        """utility function used to render the html"""
        self.render('thankyou.html')

    def get(self):
        """Function called when thankyou page is requested"""
        self.render_front()
