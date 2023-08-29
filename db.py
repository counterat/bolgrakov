import pymongo
from mongoengine import Document, FileField, ListField, StringField, connect, DateTimeField, IntField, SequenceField, ReferenceField
from mongoengine.context_managers import switch_db
from flask import jsonify
import datetime
from config import host
mongo = connect(host=host)


class Post(Document):
    id = SequenceField(primary_key=True)
    title = StringField(required=True)
    content = StringField(required=True)
    images = ListField(StringField())
    created_at = DateTimeField(default=datetime.datetime.utcnow())
    likes = IntField(default=0)
    users_who_liked = ListField(IntField(), default=[])
    author = StringField(required=True)

    def add_like(self, current_user_id):
        
        obj = Post.objects.get(id=self.id)
        obj.likes += 1
        obj.users_who_liked.append(current_user_id)
        obj.save()

        return jsonify({'likes': obj.likes})
    
    
    def remove_like(self, user_id):
        obj = Post.objects.get(id=self.id)
        obj.likes -= 1
        obj.users_who_liked.remove(user_id)
        obj.save()
        return jsonify({'likes': obj.likes})
    

class Comment(Document):
    id = SequenceField(primary_key=True)
    author = StringField(required=True)
    text = StringField(required=True)
    photo = StringField()
    post = ReferenceField(Post)
    created_at = DateTimeField(default=datetime.datetime.utcnow())

def save_post(title, content, author, images=[], likes=0, users_who_liked=[] ):
    post = Post(title=title, content=content, author=author, images=images, likes=likes, users_who_liked=users_who_liked)
    post.save() 
  
def save_comment(author, text, photo, post):
    comment = Comment(author=author, text=text, photo=photo, post=post)
    comment.save()
    print('УСПЕШНО')


""" client = pymongo.MongoClient("mongodb+srv://counteratios:0FEgDtZGAkFBhwK7@cluster0.sra50yn.mongodb.net/postsdb?retryWrites=true&w=majority")
db = client.postsdb
print(db.posts.index_information()) """

