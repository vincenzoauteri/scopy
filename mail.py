import webapp2
from google.appengine.api import mail

def send_email(source_file,address):
    fp = open(source_file, 'rb')
    content = fp.read()
    fp.close()
    user_address = address
    sender_address = "admin@scopy-me.com"
    subject = "Thank you for your interest in Scopy."
    mail.send_mail(sender_address, user_address, subject, content)
