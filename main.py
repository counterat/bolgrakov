import datetime
import werkzeug
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, make_response, render_template, request, flash, get_flashed_messages, session, redirect, abort, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta, datetime
import pymysql
from flask_login import LoginManager, login_required, login_user, UserMixin, logout_user, current_user
from flask_wtf.csrf import generate_csrf, CSRFProtect, validate_csrf
from db import *
from drive import *
from sqlalchemy import Column, Integer, String, DateTime
import random
from authlib.integrations.flask_client import OAuth
from smtp import send_verification
from config import mysql, secret, client_id, client_secret
pymysql.install_as_MySQLdb()

app = Flask(__name__, template_folder="templates")
app.config['SECRET_KEY'] = secret
app.config['SQLALCHEMY_DATABASE_URI'] = mysql
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['OAUTH2_STATE_SECURE'] = False
app.config['SERVER_NAME'] = 'localhost:5000'
app.config['PORT'] = 5000
app.register_blueprint()
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
oauth = OAuth(app)
scopes = [
    'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile'
]
google = oauth.register(
    name='google',
    client_id=client_id,
    client_secret=client_secret,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile', 'redirect_uri': 'http://localhost:5000/register/google'}
)



login_manager = LoginManager(app)
LOGIN_ATTEMPTS_LIMIT = 3
LOGIN_BLOCK_TIME = timedelta(minutes=5)
login_attempts = {}


emails_to_verify ={}




class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(2000), unique=False, nullable=False)
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    profile_photo = db.Column(db.String(2000), default='https://ru.seaicons.com/wp-content/uploads/2015/11/Users-Guest-icon.png')
    is_verified = db.Column(db.Integer, default=1)

    def __init__(self, username, email, password, profile_photo='https://ru.seaicons.com/wp-content/uploads/2015/11/Users-Guest-icon.png', is_verified=1):
        self.username = username
        self.password = password
        self.email =email
        self.profile_photo = profile_photo
        self.is_verified = is_verified

    def get_id(self):
        return self.id

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False


    def __repr__(self):
        return f"<users {self.id}>"
with app.app_context():
    db.create_all()

def existing_email(email):
    try:
        return Users.query.filter_by(email=email).first()
        
    except Exception as ex:
        return False

def existing_user(username):
    try:
        return Users.query.filter_by(username=username).first()
        
    except Exception as ex:
        return False

def user_loader(username, email, password):
    # загрузка пользователя из базы данных или другого источника данных
    return Users(username, email, password)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)



@app.route('/', methods=[ 'GET'])
def index():

    return render_template('index.html', domain='http://'+ app.config['SERVER_NAME'])


@app.route('/history.html')
def history():
    return render_template('/history.html', domain='http://'+ app.config['SERVER_NAME'])

@app.route('/proud.html')
def proud():
    return render_template('/proud.html',  domain='http://'+ app.config['SERVER_NAME'])


@app.route('/primary.html')
def primary():
    return render_template('/primary.html',  domain='http://'+ app.config['SERVER_NAME'])

@app.route('/attention.html')
def attention():
    return render_template('/attention.html',  domain='http://'+ app.config['SERVER_NAME'])


@app.route('/high-school.html')
def highschool():
    return render_template('/high-school.html',  domain='http://'+ app.config['SERVER_NAME'])

@app.route('/prevention.html')
def prevention():
    return render_template('/prevention.html',  domain='http://'+ app.config['SERVER_NAME'])

@app.route('/gymnasium-day.html')
def gymnasium():
    return render_template('/gymnasium-day.html', domain='http://'+ app.config['SERVER_NAME'])


def valid_email(email):
        
    for element in '<>()[],;:\/"*' :
        if element in email :
                
            return False
    return True
    
def isUnique(email):
    with app.app_context():
        users = Users.query.all()
        for user in users:
               
            if email == user.email:
                return False
    return True
    
def isUniqueUsername(username):
    with app.app_context():
        users = Users.query.all()
        for user in users:
               
            if username == user.username:
                return False
    return True
    
@app.route('/google_login')
def google_login():
    referer = request.args.get('state')
    print(5555555555555555)
    print(referer)
    redirect_uri = url_for('register_google', _external=True)
    state = referer
    
  


    resp = make_response(google.authorize_redirect(redirect_uri,  state = state))
    return resp

@app.route('/register/google')
def register_google():
    print(2222222)
    print(request.args.get('state'))

    token = google.authorize_access_token()
    resp = google.get('userinfo', token=token)
    user_info = resp.json()
    print(2222222)
    print(request.args.get('state'))
    if request.args.get('state') == 'register':
        u = Users(email=user_info['email'], password=user_info['id'], username=user_info['name'], profile_photo = user_info['picture'] )
        if not (isUnique(user_info['email']) and isUniqueUsername(user_info['email'])):
            return 'email чи username вже зайнято', 409
        db.session.add(u)
        db.session.flush()
        db.session.commit()
    login_user(existing_email(user_info['email']), remember=True)
    return f'Вітаємо у нашому сервісі'


@app.route('/verify_email/<int:token>', methods=['POST', 'GET'])
def verify_email(token):
    for i in emails_to_verify.keys():
        print(type(token), type(emails_to_verify.get(i)))
        if emails_to_verify.get(i) == str(token):
            
            Users.query.filter_by(email = i).first().is_verified = 1
            db.session.commit()

            del emails_to_verify[i]

            return redirect(url_for('login'))
    return 'error', 404
@app.route('/register', methods=['POST', 'GET'])
@csrf.exempt
def register():

    def valid_email(email):
        
        for element in '<>()[],;:\/"*' :
            if element in email :
                
                return False
        return True
    
    def isUnique(email):
        with app.app_context():
            users = Users.query.all()
            for user in users:
               
                if email == user.email:
                    return False
        return True
    
    def isUniqueUsername(username):
        with app.app_context():
            users = Users.query.all()
            for user in users:
               
                if username == user.username:
                    return False
        return True

    def valid_username(username):
        
        for element in '<>()[],;:\/"*':
            if element in username :
                
                return False
        return True
    try:
        
        if current_user.is_authenticated():
            return(f'''Ви вже зареєстрований користувач та увійшли у власний аккаунт<a href="/"><p>Головна</p></a> ''')
    except Exception as ex:
        print(ex)    
    
    if request.method == 'POST':
        
           
           
                username=request.form.get('username') 
                file = request.files.get('files')
                print(request.form)
       
                if ((len(request.form['password']) >= 8) and valid_email(request.form['email']) and isUnique(request.form['email']) and isUniqueUsername(username)):
                    try:
                
                        if file:
                    
                            file_link = upload_file(file)
                            file.close()
                            os.unlink(file.filename)
                            hash = generate_password_hash(request.form['password'])
                            print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                            u = Users(email=request.form['email'], password=hash, username=username, profile_photo = file_link, is_verified=0)
                            print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
                            db.session.add(u)
                            db.session.flush()
                            db.session.commit()
                            try:
                                token = str(random.randint(100000, 999999))
                                emails_to_verify[request.form['email']] = token
                                send_verification(request.form['email'], verification_link='http://'+ app.config['SERVER_NAME']+f'/verify_email/{token}')
                            except Exception as ex:
                                flash('вказана неіснуюча пошта')
                            return 'Пдітвердіть свою пошту а потім <a href="/login">увійдіть в аккаунт</a>'
                        hash = generate_password_hash(request.form['password'])
                        u = Users(email=request.form['email'], password=hash, username=username, is_verified=0)
               
                        db.session.add(u)
                        db.session.flush()
                        db.session.commit()
                        try:
                            token = str(random.randint(100000, 999999))
                            emails_to_verify[request.form['email']] = token
                            send_verification(request.form['email'], verification_link='http://'+ app.config['SERVER_NAME']+f'/verify_email/{token}')
                        except Exception as ex:
                            return f'{ex}'
                        return 'Пдітвердіть свою пошту а потім <a href="/login">увійдіть в аккаунт</a>'
                    except Exception as ex:
                        return f'{ex}'
                
                        db.session.rollback()
                if not isUniqueUsername(username):
                    flash('Це ім`я вже зайнято')

                if not (len(request.form['password']) >= 8) and valid_email(request.form['email']):
                    flash('пароль або пошта були введені некоректно')
                if not (len(username)<50 and valid_username(username)):
                    flash('Ім`я користувача повинно бути містити менше ніж 50 символів та не містити спец-символів ')
        
       

        

            
            
        

    return render_template('/lgin.html') 

@app.route('/letter')
def letter():
    
    return render_template('letter.html', username = 'Yuriy')

@app.route('/like/<int:post_id>/<csrf_token>/<int:current_user_id>', methods=['POST'])
def like(post_id, csrf_token, current_user_id):
    
    cookie_token = request.headers.get('X-CSRFToken')
   
    if csrf_token == cookie_token:
        json = Post.objects.get(id=post_id).add_like(current_user_id)
        return json
    return jsonify({'likes': "неправильно"})

@app.route('/wasliked/<int:post_id>/<csrf_token>/<int:current_user_id>', methods=['POST'])
def post_was_liked_by_user(post_id, csrf_token, current_user_id):
    cookie_token = request.headers.get('X-CSRFToken')
    if csrf_token == cookie_token:
        if current_user_id not in Post.objects.get(id=int(post_id   )).users_who_liked:
            return jsonify({'post_was_liked_by_user': False})
        return jsonify({'post_was_liked_by_user': True})
    abort(400)


@app.route('/removelike/<int:post_id>/<csrf_token>/<int:current_user_id>', methods=['POST'])
def remove_like(post_id, csrf_token, current_user_id):
    cookie_token = request.headers.get('X-CSRFToken')
   
    if csrf_token == cookie_token:
        json = Post.objects.get(id=post_id).remove_like(current_user_id)
        return json
    abort(400)

@app.route('/api/comments/<int:comment_id>/<csrf_token>', methods=['POST', 'DELETE'])
def delete_comment(comment_id, csrf_token):
    if request.headers.get('X-CSRFToken') == csrf_token:

        comment = Comment.objects(id=comment_id).first()
        comment.delete()

        return jsonify({})

@app.route('/news.html', methods=['POST', 'GET'])
@csrf.exempt
def news():
    def isAdmin():
        try:
            if current_user.email == 'bolgrakov@gmail.com':
                return True
        except Exception as ex:
            ex = 0
        return False



    if request.method == 'POST':
        
        upload_post = request.form.get('upload_post')
        upload_comment = request.form.get('upload_comment')
        like = request.form.get('like')
        print('!@!!@@!@!@!@!@!!@@!@!@!@!@!!@@!@!@!@')
        print(upload_comment=='submit')
        print(upload_post)
        if upload_post  == 'submit':
           
            print(request.files.getlist('files'))
            files = request.files.getlist('files')
            img_data = []
            for file in files:
                img_data.append(upload_file(file))
                file.close()
                os.unlink(file.filename)

            title = request.form['title']
            text = request.form['main_text']
            save_post(title, text, images =img_data, author=current_user.username)
        elif upload_comment == 'submit':
            post_id = request.form['post_id']
            try:
                if current_user.is_authenticated():
                    
                    comment = request.form.get('comment')
                    
                    print(current_user.username)
                    save_comment( author =current_user.username, text=comment, photo=current_user.profile_photo, post = Post.objects.get(id=post_id))
            
            
            except Exception as ex:
                print(post_id)
                flash(f'<a href="/register">Зареєструйтеся та увійдіть в аккаунт</a> для відправки комментарів <div style="display:none;">post_id={post_id}</div>')
        elif like == 'submit':
             return Post.objects.filter(id=request.form['post_id']).first().add_like()

    return render_template('/news.html', Post=Post, Comment1=Comment, isAdmin = isAdmin, str=str, csrf=generate_csrf(), domain='http://'+ app.config['SERVER_NAME'])


@app.route('/youth-against-war.html')
def youth():
    return render_template('/youth.html')
@app.route('/logout')
@login_required
def logout():
    
    logout_user()
    
    return(f'''Ви вийшли зі свого аккаунту<a href="/"><p>Головна</p></a> ''')

@app.route('/login', methods=['POST', 'GET'])
@csrf.exempt
def login():
    try:
        
        if current_user.is_authenticated():
            return(f'''Ви вже зареєстрований користувач та увійшли у власний аккаунт<a href="/"><p>Головна</p></a> ''')
    except Exception as ex:
        print(ex)    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form['email']
        password = request.form['password']
        checkmeout = request.form.get('checkmeout')


        user = user_loader(username, email, password)
        if username in login_attempts and \
                datetime.datetime.now() < login_attempts[username]['time'] + LOGIN_BLOCK_TIME:
                flash('Ви зробили дуже багато спроб. Зачекайте, будь ласка та спробуйте ще раз. ')
        
        else:
            if username in login_attempts:
                login_attempts[username]['count'] += 1
                login_attempts[username]['time'] = datetime.datetime.now()
            else:
                login_attempts[username] = {'count': 1, 'time': datetime.datetime.now()}

            # блокировка входа на определенное время после достижения лимита
            if login_attempts[username]['count'] >= LOGIN_ATTEMPTS_LIMIT:
                login_attempts[username]['time'] = datetime.datetime.now()
                
        if existing_email(email) and Users.query.filter_by(email=email).first().is_verified == 1 :
            if check_password_hash(existing_email(email).password, password):
                print(checkmeout)
                if checkmeout:
                    login_user(existing_email(email), remember=True)
                    
                else:
                    login_user(existing_email(email))
                    
                return redirect(url_for('index'))
            flash('Неправильна пара ""email-пароль""')

        if not Users.query.filter_by(email=email).first().is_verified == 1:
            flash('Підтвердіть свою пошту')

        flash('Неправильна пара ""email-пароль""')
        
    return render_template('/login.html')

@app.errorhandler(404)
def error404(error):
    return'404'



if __name__ == '__main__':
    app.run(debug=True)
   