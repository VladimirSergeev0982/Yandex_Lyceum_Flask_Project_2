from flask import Flask, request, render_template, redirect, session, abort, send_file
from wtforms import Form, StringField, PasswordField, TextAreaField, BooleanField, SelectField, SubmitField, HiddenField
from wtforms.validators import InputRequired, Email, EqualTo, Length, Optional, ValidationError
from hashlib import sha512
import os
from geopy.distance import geodesic
import logging

from config_file import config

from data import db_session
from data.users import User
from data.sessions import Session
from data.posts import Post

app = Flask(__name__)  # Создание экземпляра приложения
app.config['SECRET_KEY'] = config['secret_key']  # Установка параметра 'SECRET_KEY'

logging.getLogger(__name__)  # Настройка логирования
logging.basicConfig(filename='Vmeste.log', level=logging.DEBUG,
                    format='%(name)s: %(asctime)s %(levelname)s: %(message)s')


def secure_random_string(length=64):
    """Создает криптографически надежную случайную строку"""
    return ''.join([hex(b)[2:] for b in os.urandom(length)])


def get_csrf_token(session_id):
    """Возвращает CSRF токен сессии"""
    user_session = db_session.create_session().query(Session).filter(Session.id == session_id).first()
    if user_session:
        csrf_token = user_session.csrf_token
        if csrf_token:
            return csrf_token
    raise TypeError('Не удалось получить CSRF токен')


def update_csrf_token(session_id):
    """Обновляет CSRF токен сессии"""
    db_sess = db_session.create_session()
    if db_sess.query(Session).filter(Session.id == session_id).first():
        db_sess.query(Session).filter(Session.id == session_id).first().csrf_token = secure_random_string(32)
        db_sess.commit()
    else:
        raise TypeError('Не удалось изменить CSRF токен')


def get_posts_near_from_coords(coords, user_id=None):
    posts = []
    db_sess = db_session.create_session()
    for post in db_sess.query(Post):
        author = db_sess.query(User).filter(User.id == post.author).first()
        if post.location and geodesic(coords, post.location.split(';')).m <= 400 and (
                post.access == 'public' or post.author == user_id):
            posts.append((post, author))
    posts.sort(key=lambda x: x[0].created_date)
    posts.reverse()
    return posts


def check_authorization_data(user_login=None, user_id=None, password=None):
    """Валидатор формы, проверяет логин и пароль, или id и пароль"""
    if not password:
        return []
    db_sess = db_session.create_session()
    if user_login:
        user = db_sess.query(User).filter(User.email == user_login).first()
    else:
        user = db_sess.query(User).filter(User.id == user_id).first()
    if user:
        unique_salt = user.salt
        new_hash = Hash(password, use_unique_salt=True, unique_salt=unique_salt,
                        global_salt=config['global_salt'])
        old_hash = user.password
        if new_hash == old_hash:
            return []
    return [(ValidationError('Неверный логин или пароль'), 'wrong_password')]


def check_data_for_password_changing(old_password, new_password, confirm_new_password):
    """Валидатор формы, проверяет данные для смены пароля"""
    validation_errors = []
    if old_password or new_password or confirm_new_password:
        if not old_password:
            validation_errors.append(
                (ValidationError('Для смены пароля введите старый пароль'), 'old_password_not_filled'))
        if not new_password:
            validation_errors.append(
                (ValidationError('Для смены пароля введите новый пароль'), 'new_password_not_filled'))
        if not confirm_new_password:
            validation_errors.append((ValidationError('Для смены пароля подтвердите новый пароль'),
                                      'confirm_new_password_not_filled'))
    return validation_errors


def password_security_check(password):
    """Валидатор формы, проверяет надежность пароля"""
    if len(password) > 0:
        if len(password) < 8:
            return [(ValidationError('Пароль должен содержать не менее 8 символов'), 'password_is_too_easy')]
        if password.isalpha():
            return [(ValidationError('Пароль не может состоять только из букв'), 'password_is_too_easy')]
        if password.isdigit():
            return [(ValidationError('Пароль не может состоять только из цифр'), 'password_is_too_easy')]
        if password.islower():
            return [(ValidationError('Все буквы пароля не могут быть в нижнем регистре'), 'password_is_too_easy')]
        if password.isupper():
            return [(ValidationError('Все буквы пароля не могут быть в верхнем регистре'), 'password_is_too_easy')]
    return []


class Hash:
    """Класс хэша"""

    def __init__(self, string, use_unique_salt=False, unique_salt=None, global_salt=None):
        """Создание хэша. Параметры:
        string - хэшируемая строка (обязательный параметр);
        use_unique_salt - укажите значение 'True', если нужно добавить к хэшируемой строке соль;
        unique_salt - укажите соль, если нужно использовать вашу соль, иначе случайная соль будет создана автоматически;
        global_salt - укажите глобальную соль, если нужно добавить ее к строке."""
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
        """Возвращает хэш"""
        return self.hash_sha512

    def __str__(self):
        """Возвращает хэш"""
        return self.hash()

    def salt(self):
        """Возвращает уникальную соль, если она существует, иначе 'None'"""
        if self.use_unique_salt:
            return self.unique_salt
        else:
            return None

    def __eq__(self, other):
        """Метод для сравнения хэшей"""
        if isinstance(other, Hash):
            return self.hash_sha512 == other.hash_sha512
        elif isinstance(other, str):
            return self.hash_sha512 == other
        else:
            return self.hash_sha512 == str(other)

    def __ne__(self, other):
        """Метод для сравнения хэшей"""
        if isinstance(other, Hash):
            return self.hash_sha512 != other.hash_sha512
        elif isinstance(other, str):
            return self.hash_sha512 != other
        else:
            return self.hash_sha512 != str(other)


class UserSession:
    """Класс сессии"""

    def __init__(self, user_id=None, user_email=None, user=None):
        """Создание класса сессии. Параметры:
        user_id - id пользователя (необязательный параметр);
        user_email - email пользователя (необязательный параметр);
        user - тип "<class 'data.users.User'>" (необязательный параметр)."""
        if user_id:
            self.user_id = user_id
        elif user_email:
            self.user_id = db_session.create_session().query(User).filter(User.email == user_email).first().id
        elif user:
            self.user_id = user.id
        self.user_id = user_id
        self.session_exists = False

    def check_session(self):
        """Проверяет существование сессии"""
        if self.session_exists:
            return True
        else:
            key = session.get('session_key', None)
            session_id = session.get('session_id', None)
            if key and session_id:
                user_sessions = db_session.create_session().query(Session).filter(Session.id == session_id)
                if user_sessions:
                    for user_session in user_sessions:
                        unique_salt = user_session.salt
                        new_hash = Hash(key, use_unique_salt=True, unique_salt=unique_salt,
                                        global_salt=config['global_salt'])
                        old_hash = user_session.key
                        if new_hash == old_hash:
                            self.user_id = user_session.user
                            self.session_exists = True
                            return True
            return False

    def get_user_id(self):
        """Возвращает id пользователя (перед использованием необходимо применить к экземпляру класса метод '.check_session()')"""
        return self.user_id

    def get_user(self):
        """Возвращает тип "<class 'data.users.User'>" (перед использованием необходимо применить к экземпляру класса метод '.check_session()')"""
        return db_session.create_session().query(User).filter(User.id == self.user_id).first()

    def create_session(self, user_id=None, user_email=None, user=None, remember_user=False):
        """Создает сессию. Параметры:
        user_id - id пользователя (необязательный параметр);
        user_email - логин пользователя (необязательный параметр);
        user - тип "<class 'data.users.User'>" (необязательный параметр);
        remember_user - укажите 'True', если нужно сохранить сессию после закрытия браузера (необязательный параметр)."""
        db_sess = db_session.create_session()
        if not self.user_id:
            if user_id:
                self.user_id = user_id
            elif user_email:
                self.user_id = db_sess.query(User).filter(User.email == user_email).first().id
            elif user:
                self.user_id = user.id
            else:
                raise TypeError('Не найдено id пользователя')
        user_session = Session()
        user_session.user = self.user_id
        key = secure_random_string()
        key_hash = Hash(key, use_unique_salt=True, global_salt=config['global_salt'])
        user_session.key = key_hash.hash()
        user_session.salt = key_hash.salt()
        db_sess.add(user_session)
        db_sess.commit()
        update_csrf_token(user_session.id)
        session['session_key'] = key
        session['session_id'] = user_session.id
        session.permanent = remember_user
        self.session_exists = True

    def delete_session(self):
        """Удаляет сессию (перед использованием необходимо применить к экземпляру класса метод '.check_session()')"""
        if self.session_exists:
            session_id = session.get('session_id', None)
            db_sess = db_session.create_session()
            db_sess.query(Session).filter(Session.id == session_id).delete()
            db_sess.commit()
            session.pop('session_key', None)
            session.pop('session_id', None)
            self.session_exists = False

    def delete_all_user_sessions(self, user_id=None, user_email=None, user=None):
        """Удаляет все сессии пользователя
        (перед использованием необходимо применить к экземпляру класса метод '.check_session()').
        Параметры:
        user_id - id пользователя (необязательный параметр);
        user_email - логин пользователя (необязательный параметр);
        user - тип "<class 'data.users.User'>" (необязательный параметр).
        """
        if self.session_exists:
            db_sess = db_session.create_session()
            if not self.user_id:
                if user_id:
                    self.user_id = user_id
                elif user_email:
                    self.user_id = db_sess.query(User).filter(User.email == user_email).first().id
                elif user:
                    self.user_id = user.id
                else:
                    raise TypeError('Не найдено id пользователя')
            db_sess.query(Session).filter(Session.user == self.user_id).delete()
            db_sess.commit()
            session.pop('session_key', None)
            session.pop('session_id', None)
            self.session_exists = False


class IsFree:
    """Валидатор формы, проверяет занят ли логин. Параметры:
    validation_exception - укажите логин пользователя, если его необходино исключить при проверке (необязательный параметр)."""

    def __init__(self, message=None, validation_exception=None):
        self.validation_exception = validation_exception
        if not message:
            message = 'Этот email адрес занят'
        self.message = message

    def __call__(self, form, field):
        if db_session.create_session().query(User).filter(
                (User.email == field.data)).first() and field.data != self.validation_exception:
            raise ValidationError(self.message)


class LoginForm(Form):
    """Форма для входа"""
    email = StringField('Email', [InputRequired(message='Введите email')])
    password = PasswordField('Пароль', [InputRequired(message='Введите пароль')])
    remember_user = BooleanField('Запомнить меня')
    submit = SubmitField()


class RegisterForm(Form):
    """Форма для регистрации"""
    name = StringField('Полное имя',
                       [InputRequired(message='Введите имя'), Length(min=3, max=1000, message='Имя слишком короткое')])
    email = StringField('Email', [InputRequired(message='Введите email'),
                                  Email(message='Неверный email', check_deliverability=False),
                                  IsFree(message='Пользователь с таким email уже зарегистрирован')])
    password = PasswordField('Пароль', [InputRequired(message='Введите пароль')])
    confirm_password = PasswordField('Подтвердите пароль', [InputRequired(message='Подтвердите пароль'),
                                                            EqualTo('password', message='Пароли должны совпадать')])
    about = TextAreaField('Расскажите о себе', [Optional(), Length(max=10000)])
    submit = SubmitField()


def get_add_post_form():
    """Возвращает экземпляр класса 'AddPostForm'"""

    class AddPostForm(Form):
        """Форма для добавления постов"""
        csrf_token = HiddenField(default=get_csrf_token(session.get('session_id', None)))
        title = StringField('Заголовок поста', [InputRequired(message='Введите заголовок поста'), Length(max=1000)])
        content = TextAreaField('Текст поста', [InputRequired(message='Введите текст поста'), Length(max=10000)])
        access = SelectField('Доступ', choices=[('private', 'Приватный'), ('public', 'Публичный')])
        submit = SubmitField()

    return AddPostForm(request.form)


def get_delete_account_form():
    """Возвращает экземпляр класса 'DeleteAccountForm'"""

    class DeleteAccountForm(Form):
        """Форма для удаления аккаунта"""
        csrf_token = HiddenField(default=get_csrf_token(session.get('session_id', None)))
        password = PasswordField('Пароль', [InputRequired(message='Введите пароль')])
        confirm = BooleanField('Я понимаю, что не смогу восстановить аккаунт и согласен с этим.',
                               [InputRequired(message='Пожалуйста отметьте')])
        submit = SubmitField()

    return DeleteAccountForm(request.form)


def get_edit_profile_form(user):
    """Возвращает экземпляр класса 'EditProfileForm'"""

    class EditProfileForm(Form):
        """Форма для редактирования профиля"""
        csrf_token = HiddenField(default=get_csrf_token(session.get('session_id', None)))
        name = StringField('Полное имя', [Optional(), Length(min=3, max=1000, message='Имя слишком короткое')],
                           default=user.name)
        email = StringField('Email', [Optional(), Email(message='Неверный email', check_deliverability=False),
                                      IsFree(validation_exception=user.email)], default=user.email)
        about = TextAreaField('О себе', [Optional(), Length(max=10000)], default=user.about)
        old_password = PasswordField('Старый пароль', [Optional()])
        new_password = PasswordField('Новый пароль', [Optional()])
        confirm_new_password = PasswordField('Подтвердите новый пароль',
                                             [Optional(), EqualTo('new_password', message='Пароли должны совпадать')])
        submit = SubmitField()

    return EditProfileForm(request.form)


@app.route('/map', methods=["GET"])
def show_map():  # TODO
    """Страница с картой"""
    user_session = UserSession()
    user_session.check_session()
    number_of_posts = 0
    number_of_chats = 0
    coords = request.args.get("ll")
    zoom = request.args.get("z")
    if coords:
        coords = [float(i) for i in coords.split(',')]
        map_coords = coords
        point_coords = coords
        number_of_posts = len(get_posts_near_from_coords(coords, user_id=user_session.get_user_id()))
    else:
        map_coords = [56.14561517712219, 47.244224423534234]
        point_coords = None
    if not zoom:
        zoom = 15
    param = {
        'title': 'Карта',
        'session': user_session.check_session(),
        'map_coords': map_coords,
        'point_coords': point_coords,
        'zoom': zoom,
        'number_of_posts': number_of_posts,
        'number_of_chats': number_of_chats
    }
    return render_template('map.html', **param)


@app.route('/posts', methods=["GET", "POST"])
def show_posts():  # TODO
    """Страница с постами"""
    user_session = UserSession()
    coords = request.args.get("ll")
    if coords:
        form = None
        if user_session.check_session():
            form = get_add_post_form()
        coords = [float(i) for i in coords.split(',')]
        if request.method == 'POST' and form.validate() and user_session.check_session():
            session_id = session.get('session_id', None)
            if form.csrf_token.data != get_csrf_token(session_id):
                return redirect(f'/posts?ll={",".join([str(i) for i in coords])}')
            new_post = Post()
            new_post.title = form.title.data
            new_post.content = form.content.data
            new_post.location = ';'.join((str(coords[0]), str(coords[1])))
            new_post.author = user_session.get_user_id()
            new_post.access = form.access.data
            db_sess = db_session.create_session()
            db_sess.add(new_post)
            db_sess.commit()
            update_csrf_token(session_id)
        posts = get_posts_near_from_coords(coords, user_id=user_session.get_user_id())
        param = {
            'title': 'Посты',
            'session': user_session.check_session(),
            'session_object': user_session,
            'posts': posts,
            'coords': coords
        }
        return render_template('posts.html', form=form, **param)
    abort(404)


@app.route('/post', methods=["GET", "POST"])
def show_post():  # TODO
    """Страница просмотра отдельного поста"""
    user_session = UserSession()
    post_id = request.args.get("id")
    db_sess = db_session.create_session()
    post = db_sess.query(Post).filter(Post.id == post_id).first()
    param = {
        'title': post.title,
        'session': user_session.check_session(),
        'session_object': user_session,
        'post': post,
        'autor': db_sess.query(User).filter(User.id == post.author).first().name
    }
    return render_template('post.html', **param)


@app.route('/')
@app.route('/index')
def index():  # TODO
    """Главная страница"""
    user_session = UserSession()
    param = {
        'title': 'Главная',
        'session': user_session.check_session()
    }
    return render_template('bung.html', **param)


@app.route('/my_profile')
def my_profile():
    """Если пользователь зарегестрированн, отправляет его на страницу его профиля, иначе на страницу входа"""
    user_session = UserSession()
    if user_session.check_session():
        return redirect(f'/user?id={user_session.get_user_id()}')
    else:
        return redirect('/login')


@app.route('/edit_profile', methods=['POST', 'GET'])
def edit_profile():
    """Страница редактирования профиля"""
    user_session = UserSession()
    if user_session.check_session():
        changes_successfully_applied = False
        validation_errors = []
        form = get_edit_profile_form(user_session.get_user())
        if request.method == 'POST' and form.validate():
            user_id = user_session.get_user_id()
            validation_errors += check_data_for_password_changing(old_password=form.old_password.data,
                                                                  new_password=form.new_password.data,
                                                                  confirm_new_password=form.confirm_new_password.data)
            validation_errors += check_authorization_data(user_id=user_id,
                                                          password=form.old_password.data)
            validation_errors += password_security_check(form.new_password.data)
            if not validation_errors:
                session_id = session.get('session_id', None)
                if form.csrf_token.data != get_csrf_token(session_id):
                    return redirect('/edit_profile')
                db_sess = db_session.create_session()
                user = db_sess.query(User).filter(User.id == user_id).first()
                user.name = form.name.data
                user.email = form.email.data
                user.about = form.about.data
                if form.new_password.data:
                    password_hash = Hash(form.new_password.data, use_unique_salt=True,
                                         global_salt=config['global_salt'])
                    user.password = password_hash.hash()
                    user.salt = password_hash.salt()
                    user.security_level = config['security_level']
                db_sess.commit()
                changes_successfully_applied = True
                update_csrf_token(session_id)
        param = {
            'title': 'Редактирование профиля',
            'session': user_session.check_session(),
            'errors': validation_errors,
            'changes_successfully_applied': changes_successfully_applied
        }
        return render_template('edit_profile.html', form=form, **param)
    else:
        return redirect('/login')


@app.route('/delete_account', methods=['POST', 'GET'])
def delete_account():
    """Страница для удаления аккаунта"""
    user_session = UserSession()
    if user_session.check_session():
        validation_errors = []
        form = get_delete_account_form()
        if request.method == 'POST' and form.validate():
            user_id = user_session.get_user_id()
            validation_errors += check_authorization_data(user_id=user_id, password=form.password.data)
            if not validation_errors:
                session_id = session.get('session_id', None)
                if form.csrf_token.data != get_csrf_token(session_id):
                    return redirect('/delete_account')
                db_sess = db_session.create_session()
                db_sess.query(User).filter(User.id == user_id).delete()
                db_sess.query(Post).filter(Post.author == user_id).delete()
                db_sess.commit()
                user_session.delete_all_user_sessions(user_id=user_id)
                return redirect('/')
        param = {
            'title': 'Удаление аккаунта',
            'session': user_session.check_session(),
            'errors': validation_errors
        }
        return render_template('delete_account.html', form=form, **param)
    else:
        return redirect('/login')


@app.route('/user', methods=['GET'])
def show_user():
    """Страница просмотра профиля пользователя"""
    user_session = UserSession()
    user_id = int(request.args.get("id"))
    user = db_session.create_session().query(User).filter(User.id == user_id).first()
    if user:
        param = {
            'title': user.name,
            'session': user_session.check_session(),
            'user': user,
            'user_is_account_owner': user_session.get_user_id() == user_id
        }
        return render_template('user.html', **param)
    else:
        abort(404)


@app.route('/login', methods=['POST', 'GET'])
def login():
    """Страница входа"""
    user_session = UserSession()
    if not user_session.check_session():
        validation_errors = []
        form = LoginForm(request.form)
        if request.method == 'POST' and form.validate():
            validation_errors += check_authorization_data(user_login=form.email.data, password=form.password.data)
            if not validation_errors:
                user_session.create_session(user_email=form.email.data, remember_user=form.remember_user.data)
                return redirect('/map')
        param = {
            'title': 'Вход',
            'session': user_session.check_session(),
            'errors': validation_errors
        }
        return render_template('login.html', form=form, **param)
    else:
        return redirect('/map')


@app.route('/register', methods=['POST', 'GET'])
def register():
    """Страница регистрации"""
    user_session = UserSession()
    if not user_session.check_session():
        validation_errors = []
        form = RegisterForm(request.form)
        if request.method == 'POST' and form.validate():
            validation_errors += password_security_check(form.password.data)
            if not validation_errors:
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
            'title': 'Регистрация',
            'session': user_session.check_session(),
            'errors': validation_errors
        }
        return render_template('register.html', form=form, **param)
    else:
        return redirect("/my_profile")


@app.route('/logout')
def logout():
    """Осуществляет выход из профиля"""
    user_session = UserSession()
    if user_session.check_session():
        user_session.delete_session()
    return redirect("/")


@app.route('/about')
@app.route('/help')
def about():  # TODO
    """Страница с информацией"""
    user_session = UserSession()
    param = {
        'title': 'Информация',
        'session': user_session.check_session()
    }
    try:
        with open('../README.md', mode='r', encoding='utf-8') as f:
            param['lines'] = f.readlines()
    except FileNotFoundError as e:
        param['lines'] = [e]
    return render_template('about.html', **param)


@app.route('/download', methods=['GET'])
def download():
    """Страница для скачивания файлов"""
    try:
        return send_file(f'..docs/{request.args.get("file")}')
    except OSError as e:
        return str(e)


@app.route('/change_password')
def change_password():
    user_session = UserSession()
    if user_session:
        return redirect('/edit_profile')
    else:
        return redirect('/login')


@app.route('/invalid_csrf_token')
def invalid_csrf_token():
    user_session = UserSession()
    param = {
        'title': 'Недопустимый CSRF токен',
        'session': user_session.check_session()
    }
    return render_template('InvalidCSRFToken.html', **param)


@app.errorhandler(404)
def not_found(e):
    """Страница с ошибкой 404"""
    user_session = UserSession()
    param = {
        'title': 'Не найдено',
        'session': user_session.check_session()
    }
    return render_template('NotFound.html', **param)


@app.errorhandler(500)
def internal_server_error(e):
    """Страница с ошибкой 500"""
    user_session = UserSession()
    param = {
        'title': 'Ошибка',
        'session': user_session.check_session()
    }
    return render_template('InternalServerError.html', **param)


if __name__ == '__main__':
    if not os.path.isdir("db"):
        os.mkdir("db")
    db_session.global_init("db/VMeste.db")  # Вызов глобальной инициализации всего, что связано с базой данных
    port = int(os.environ.get("PORT", 5000))  # Получение порта
    app.run(host='0.0.0.0', port=port, debug=False)  # Запуск приложения
