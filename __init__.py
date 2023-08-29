from mongoengine import Document, FileField, ListField, StringField, connect, DateTimeField
from bot import start_bot
from main import app
mongo = connect(host='mongodb+srv://counteratios:0FEgDtZGAkFBhwK7@cluster0.sra50yn.mongodb.net/postsdb?retryWrites=true&w=majority')
