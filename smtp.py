import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
import random
from flask import render_template

def send_verification(to_email, verification_link):
    # Email configuration
    from_email = 'bolgrakov@gmail.com'
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    
    smtp_password = 'tfilcbcyknqkfujb'

    # Create message
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = 'Please verify your email address'
    
    # Email body
    text = render_template('letter.html', verification_link=verification_link )

    msg.attach(MIMEText(text, 'html'))
    # Connect to SMTP server and send message
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.ehlo()
    server.starttls()
    server.login(from_email, smtp_password)
    server.sendmail(from_email, to_email, msg.as_string())
    print('ezzzzzzzz')
    server.quit()

