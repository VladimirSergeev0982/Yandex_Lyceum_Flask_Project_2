from flask import Flask, request, render_template, redirect, abort, send_file, g, session, flash
from wtforms import Form, StringField, PasswordField, TextAreaField, BooleanField, SubmitField, HiddenField
from wtforms.validators import InputRequired, Email, EqualTo, Length, Optional, ValidationError
import werkzeug
import sqlite3
from hashlib import sha512
from os import urandom
import os
import folium

from scripts.FDataBase import FDataBase
from config_file import config

from data import db_session
from data.users import User
from data.sessions import Session

app = Flask(__name__)
app.config['SECRET_KEY'] = config['secret_key']
app.config['DATABASE'] = 'db/flsite.db'
dbase = None


def connect_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn


def create_db():
    db = connect_db()
    with app.open_resource('scripts/sq_db.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    db.close()


def get_db() -> object:
    if not hasattr(g, 'link_db'):
        g.link_db = connect_db()
    return g.link_db


@app.before_request
def before_request():
    global dbase
    db = get_db()
    dbase = FDataBase(db)


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'link_db'):
        g.link_db.close()


def secure_random_string(length=64):
    return ''.join([hex(b)[2:] for b in urandom(length)])


class Hash:
    def __init__(self, string, use_unique_salt=False, unique_salt=None, global_salt=None):
        self.use_unique_salt = use_unique_salt
        self.unique_salt = unique_salt
        if self.use_unique_salt:
            if not self.unique_salt:
                self.unique_salt = secure_random_string()
        else:
            self.unique_salt = ''
        if not global_salt:
            global_salt = ''
        self.hash_sha512 = sha512(
            str(string).encode('utf-8') + self.unique_salt.encode('utf-8') + global_salt.encode('utf-8')).hexdigest()

    def hash(self):
        return self.hash_sha512

    def __str__(self):
        return self.hash()

    def salt(self):
        if self.use_unique_salt:
            return self.unique_salt
        else:
            return None

    def __eq__(self, other):
        if isinstance(other, Hash):
            return self.hash_sha512 == other.hash_sha512
        elif isinstance(other, str):
            return self.hash_sha512 == other
        else:
            try:
                return self.hash_sha512 == str(other)
            except Exception:
                return False

    def __ne__(self, other):
        if isinstance(other, Hash):
            return self.hash_sha512 != other.hash_sha512
        elif isinstance(other, str):
            return self.hash_sha512 != other
        else:
            try:
                return self.hash_sha512 != str(other)
            except Exception:
                return False


class User_Session:
    def __init__(self, user_id=None, user=None):
        if not user_id and user:
            user_id = user.id
        self.user_id = user_id

    def check_session(self):
        if self.user_id:
            return True
        else:
            key = session.get('session_key', None)
            user_id = session.get('user_id', None)
            if key and user_id:
                db_sess = db_session.create_session()
                if db_sess.query(Session).filter(Session.user == user_id).first():
                    unique_salt = db_sess.query(Session).filter(Session.user == user_id).first().salt
                    new_hash = Hash(key, use_unique_salt=True, unique_salt=unique_salt,
                                    global_salt=config['global_salt'])
                    old_hash = db_sess.query(Session).filter(Session.user == user_id).first().key
                    if new_hash == old_hash:
                        self.user_id = user_id
                        return True
            return False

    def get_user_id(self):
        return self.user_id

    def get_user(self):
        return db_session.create_session().query(User).filter(User.id == self.user_id).first()

    def create_session(self, user_id=None, user_email=None, user=None, remember_user=False):
        if not self.user_id:
            if user_id:
                self.user_id = user_id
            elif user_email:
                self.user_id = db_session.create_session().query(User).filter(User.email == user_email).first().id
            elif user:
                self.user_id = user.id
            else:
                raise TypeError('Не найдено id пользователя')
        db_sess = db_session.create_session()
        db_sess.query(Session).filter(Session.user == self.user_id).delete()
        user_session = Session()
        user_session.user = self.user_id
        key = secure_random_string()
        key_hash = Hash(key, use_unique_salt=True, global_salt=config['global_salt'])
        user_session.key = key_hash.hash()
        user_session.salt = key_hash.salt()
        db_sess.add(user_session)
        db_sess.commit()
        session['session_key'] = key
        session['user_id'] = self.user_id
        session.permanent = remember_user

    def delete_session(self, user_id=None, user_email=None, user=None):
        if not self.user_id:
            if user_id:
                self.user_id = user_id
            elif user_email:
                self.user_id = db_session.create_session().query(User).filter(User.email == user_email).first().id
            elif user:
                self.user_id = user.id
            else:
                raise TypeError('Не найдено id пользователя')
        db_sess = db_session.create_session()
        db_sess.query(Session).filter(Session.user == self.user_id).delete()
        db_sess.commit()
        session.pop('session_key', None)
        session.pop('user_id', None)


class Password_security_check:
    def __call__(self, form, field):
        if len(field.data) < 8:
            raise ValidationError('Пароль должен содержать не менее 8 символов')
        if field.data.isalpha():
            raise ValidationError('Пароль не может состоять только из букв')
        if field.data.isdigit():
            raise ValidationError('Пароль не может состоять только из цифр')
        if field.data.islower():
            raise ValidationError('Все буквы пароля не могут быть в нижнем регистре')
        if field.data.isupper():
            raise ValidationError('Все буквы пароля не могут быть в верхнем регистре')


class Is_free:
    def __init__(self, message=None):
        if not message:
            message = 'Пользователь с таким email уже зарегистрирован'
        self.message = message

    def __call__(self, form, field):
        if db_session.create_session().query(User).filter(User.email == field.data).first():
            raise ValidationError(self.message)


class Check_login_and_password:
    def __init__(self):
        self.login = None
        self.password = None

    def send_login(self, login):
        self.login = login
        if self.password:
            return self.check()

    def sent_password(self, password):
        self.password = password
        if self.password:
            return self.check()

    def check(self):
        if config['security_level'] == '0.1':
            db_sess = db_session.create_session()
            if db_sess.query(User).filter(User.email == self.login).first():
                unique_salt = db_sess.query(User).filter(User.email == self.login).first().salt
                new_hash = Hash(self.password, use_unique_salt=True, unique_salt=unique_salt,
                                global_salt=config['global_salt'])
                old_hash = db_sess.query(User).filter(User.email == self.login).first().password
                return new_hash == old_hash
            else:
                return False


check_login_and_password = Check_login_and_password()


class Send_login_to_check:
    def __call__(self, form, field):
        check_login_and_password.send_login(field.data)


class Send_password_to_check:
    def __init__(self, message=None):
        if not message:
            message = 'Неверный логин или пароль'
        self.message = message

    def __call__(self, form, field):
        if not check_login_and_password.sent_password(field.data):
            raise ValidationError(self.message)


class LoginForm(Form):
    email = StringField('Email', [InputRequired(message='Введите email'), Send_login_to_check()])
    password = PasswordField('Пароль', [InputRequired(message='Введите пароль'), Send_password_to_check()])
    remember_user = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


class RegisterForm(Form):
    name = StringField('Полное имя',
                       [InputRequired(message='Введите имя'), Length(min=3, max=1000, message='Имя слишком короткое')])
    email = StringField('Email', [InputRequired(message='Введите email'),
                                  Email(message='Неверный email', check_deliverability=True), Is_free()])
    password = PasswordField('Пароль', [InputRequired(message='Введите пароль'), Password_security_check()])
    confirm_password = PasswordField('Подтвердите пароль', [InputRequired(message='Подтвердите пароль'),
                                                            EqualTo('password', message='Пароли должны совпадать')])
    about = TextAreaField('Расскажите о себе', [Optional(), Length(max=10000)])
    submit = SubmitField('Зарегистрироваться')


@app.route('/')  # TODO
@app.route('/index')
def index():
    abort(501)


@app.route('/profile', methods=['POST', 'GET'])  # TODO
def profile():
    user_session = User_Session()
    if user_session.check_session():
        csrf_token = secure_random_string()

        class EditForm(Form):
            form_csrf_token = HiddenField(default=csrf_token)
            name = StringField('Полное имя', [InputRequired(message='Введите имя'),
                                              Length(min=3, max=1000, message='Имя слишком короткое')],
                               default=user_session.get_user().name)
            email = StringField('Email', [InputRequired(message='Введите email'),
                                          Email(message='Неверный email', check_deliverability=True), Is_free()],
                                default=user_session.get_user().email)
            about = TextAreaField('О себе', [Optional(), Length(max=10000)], default=user_session.get_user().about)
            submit = SubmitField('Сохранить')

        form = EditForm(request.form)
        if request.method == 'POST' and form.validate():
            if form.form_csrf_token.data != csrf_token:
                return redirect('/profile')
            db_sess = db_session.create_session()
            user_id = user_session.get_user_id()
            if form.name:
                db_sess.query(User).filter(User.id == user_id).first().name = form.name.data
            if form.email:
                db_sess.query(User).filter(User.id == user_id).first().email = form.email.data
            if form.about:
                db_sess.query(User).filter(User.id == user_id).first().about = form.about.data
            db_sess.commit()
        param = {
            'page_name': 'Мой профиль',
            'session': user_session.check_session(),
            'user': user_session.get_user()
        }
        return render_template('profile.html', form=form, **param)
    else:
        return redirect('/login')


@app.route('/map')
def base():
    map = folium.Map(location=[56.11677, 47.26278])
    return map._repr_html_()


@app.route('/open-street-map')
def open_sreet_map():
    map = folium.Map(location=[56.11677, 47.26278],
                     tiles='Stamen Toner',
                     zoom_start=13
                     )
    return map._repr_html_()


@app.route('/map-marker')
def map_marker():
    map = folium.Map(location=[56.11677, 47.26278],
                     tiles='Stamen Terrain',
                     zoom_start=13
                     )
    folium.Marker(location=[56.13677, 47.24278],
                  popup='<b> <a href="/open-street-map"> Новости Ленинского района </a> </b>',
                  tooltip='Ленинский район',
                  icon=folium.Icon(color='blue')
                  ).add_to(map)

    folium.Marker(location=[56.13677, 47.30278],
                  popup='<b> <a href="/open-street-map"> Новости Калининкого района </a> </b>',
                  tooltip='Калининский район',
                  icon=folium.Icon(color='green')
                  ).add_to(map)

    folium.Marker(location=[56.14677, 47.22278],
                  popup='<b> <a href="/open-street-map"> Новости Московского района </a> </b>',
                  tooltip='Московский район',
                  icon=folium.Icon(color='red')
                  ).add_to(map)

    return map._repr_html_()


@app.route("/add_post", methods=["POST", "GET"])
def addPost():
    if request.method == "POST":
        if len(request.form['name']) > 20 and len(request.form['post']) > 40:
            res = dbase.addPost(request.form['name'], request.form['post'], request.form['url'])
            if not res:
                flash('Ошибка добавления статьи', category='error')
            else:
                flash('Статья добавлена успешно', category='success')
        else:
            flash('Ошибка добавления статьи', category='error')

    return render_template('add_post.html', menu=dbase.getMenu(), title="Добавление статьи")


@app.route("/post/<alias>")
def showPost(alias):
    title, post = dbase.getPost(alias)
    if not title:
        abort(404)

    return render_template('post.html', menu=dbase.getMenu(), title=title, post=post)


@app.route('/login', methods=['POST', 'GET'])
def login():
    user_session = User_Session()
    if not user_session.check_session():
        form = LoginForm(request.form)
        if request.method == 'POST' and form.validate():
            user_session.create_session(user_email=form.email.data, remember_user=form.remember_user.data)
            return redirect('/map')
        param = {
            'page_name': 'Вход',
            'session': user_session.check_session()
        }
        return render_template('login.html', form=form, **param)
    else:
        return redirect('/map')


@app.route('/register', methods=['POST', 'GET'])
def register():
    user_session = User_Session()
    if not user_session.check_session():
        form = RegisterForm(request.form)
        if request.method == 'POST' and form.validate():
            user = User()
            user.name = form.name.data
            user.about = form.about.data
            user.email = form.email.data
            password_hash = Hash(form.password.data, use_unique_salt=True, global_salt=config['global_salt'])
            user.password = password_hash.hash()
            user.salt = password_hash.salt()
            user.security_level = config['security_level']
            db_sess = db_session.create_session()
            db_sess.add(user)
            db_sess.commit()
            return redirect('/login')
        param = {
            'page_name': 'Регистрация',
            'session': user_session.check_session()
        }
        return render_template('register.html', form=form, **param)
    else:
        return redirect("/profile")


@app.route('/logout')
def logout():
    user_session = User_Session()
    if user_session.check_session():
        user_session.delete_session()
    return redirect("/")


@app.route('/about')
@app.route('/help')
def about():
    user_session = User_Session()
    param = {
        'page_name': 'Информация',
        'session': user_session.check_session()
    }
    try:
        with open('../README.md', mode='r', encoding='utf-8') as f:
            param['lines'] = f.readlines()
    except FileNotFoundError as e:
        param['lines'] = [e]
    return render_template('about.html', **param)


@app.route('/download/', methods=['GET'])
def download():
    try:
        return send_file(f'../docs/{request.args.get("file")}')
    except FileNotFoundError as e:
        return str(e)


@app.errorhandler(werkzeug.exceptions.NotFound)
def NotFound(e):
    user_session = User_Session()
    param = {
        'page_name': 'Не найдено',
        'session': user_session.check_session()
    }
    return render_template('NotFound.html', **param)


@app.errorhandler(werkzeug.exceptions.NotImplemented)
def NotImplemented(e):
    user_session = User_Session()
    param = {
        'page_name': 'Не реализовано',
        'session': user_session.check_session()
    }
    return render_template('NotImplemented.html', **param)


if __name__ == '__main__':
    db_session.global_init("db/VMeste.db")
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
