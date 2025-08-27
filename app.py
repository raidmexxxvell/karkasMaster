"""
Единый app.py — Flask + TeleBot + SocketIO + SQLAlchemy + Redis
Шаблоны HTML лежат в папке templates.
"""

import os
import json
import time
import threading
from queue import Queue, Empty
from datetime import datetime

from flask import Flask, request, redirect, url_for, abort, render_template, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import telebot
from telebot import types
import hmac
import hashlib
import urllib.parse
from sqlalchemy import (create_engine, Column, Integer, String, Text, DateTime, ForeignKey)
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
import redis
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Env
BOT_TOKEN = os.getenv('BOT_TOKEN')
BOT_USERNAME = os.getenv('BOT_USERNAME')
DATABASE_URL = os.getenv('DATABASE_URL')
REDIS_URL = os.getenv('REDIS_URL')
OWNER_TELEGRAM_ID = os.getenv('OWNER_TELEGRAM_ID')
INITIAL_ADMINS = os.getenv('INITIAL_ADMINS', '')
APP_URL = os.getenv('APP_URL')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET', 'change_me_in_prod')

socketio = SocketIO(app, cors_allowed_origins='*', message_queue=REDIS_URL, async_mode='threading')
bot = telebot.TeleBot(BOT_TOKEN) if BOT_TOKEN else None
redis_client = redis.from_url(REDIS_URL) if REDIS_URL else None

# SQLAlchemy
Base = declarative_base()
engine = create_engine(DATABASE_URL or 'sqlite:///data.db', echo=False, future=True)
SessionLocal = sessionmaker(bind=engine)

class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), unique=True, nullable=False)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    telegram_id = Column(String(64), unique=True, nullable=False)
    name = Column(String(128))
    role_id = Column(Integer, ForeignKey('roles.id'))
    role = relationship('Role')
    def is_admin(self):
        return self.role and self.role.name in ('admin', 'owner')

class Project(Base):
    __tablename__ = 'projects'
    id = Column(Integer, primary_key=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    main_photo_url = Column(String(500))
    extra_photos_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class Membership(Base):
    __tablename__ = 'memberships'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    project_id = Column(Integer, ForeignKey('projects.id'))
    role = Column(String(32), default='worker')
    joined_at = Column(DateTime, default=datetime.utcnow)
    user = relationship('User')
    project = relationship('Project')

class Message(Base):
    __tablename__ = 'messages'
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'), index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    text = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship('User')
    project = relationship('Project')

class UserPhoto(Base):
    __tablename__ = 'user_photos'
    user_id = Column(Integer, primary_key=True)  # store telegram user id as int
    photo_url = Column(String(500))
    updated_at = Column(DateTime, default=datetime.utcnow)


class Activity(Base):
    __tablename__ = 'activities'
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'), index=True)
    actor_user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    type = Column(String(64), default='note')  # note, task_created, status_changed, message
    text = Column(Text)
    metadata = Column(Text)  # JSON as text for simple extensibility
    created_at = Column(DateTime, default=datetime.utcnow)
    project = relationship('Project')
    actor = relationship('User')


class ActivityComment(Base):
    __tablename__ = 'activity_comments'
    id = Column(Integer, primary_key=True)
    activity_id = Column(Integer, ForeignKey('activities.id'), index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    text = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    activity = relationship('Activity')
    user = relationship('User')


class Task(Base):
    __tablename__ = 'tasks'
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'), index=True)
    title = Column(String(300))
    status = Column(String(32), default='open')
    assignee_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    project = relationship('Project')
    assignee = relationship('User')

def init_db():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        for r in ('owner','admin','worker','user'):
            if not session.query(Role).filter_by(name=r).first():
                session.add(Role(name=r))
        session.commit()
        owner_tid = str(OWNER_TELEGRAM_ID) if OWNER_TELEGRAM_ID else None
        if owner_tid:
            owner = session.query(User).filter_by(telegram_id=owner_tid).first()
            owner_role = session.query(Role).filter_by(name='owner').first()
            if not owner:
                owner = User(telegram_id=owner_tid, name='Owner', role=owner_role)
                session.add(owner)
        admins = [s.strip() for s in INITIAL_ADMINS.split(',') if s.strip()]
        admin_role = session.query(Role).filter_by(name='admin').first()
        for a in admins[:2]:
            if a:
                u = session.query(User).filter_by(telegram_id=str(a)).first()
                if not u:
                    u = User(telegram_id=str(a), name=f'Admin {a}', role=admin_role)
                    session.add(u)
        session.commit()
    finally:
        session.close()

init_db()

PROJECTS_CACHE_KEY = 'projects_cache_v1'
PROJECTS_CACHE_TTL = 60

def get_projects_cached():
    if not redis_client:
        session = SessionLocal()
        try:
            return session.query(Project).all()
        finally:
            session.close()
    data = redis_client.get(PROJECTS_CACHE_KEY)
    if data:
        return json.loads(data)
    session = SessionLocal()
    try:
        projects = session.query(Project).all()
        out = []
        for p in projects:
            out.append({'id': p.id, 'title': p.title, 'description': p.description, 'main_photo_url': p.main_photo_url, 'extra_photos': json.loads(p.extra_photos_json or '[]')})
        redis_client.setex(PROJECTS_CACHE_KEY, PROJECTS_CACHE_TTL, json.dumps(out))
        return out
    finally:
        session.close()

ADMIN_TOKEN_TTL = 300

def generate_admin_token(telegram_id):
    import secrets
    token = secrets.token_urlsafe(16)
    key = f'admin_token:{token}'
    if redis_client:
        redis_client.setex(key, ADMIN_TOKEN_TTL, str(telegram_id))
    return token

def validate_admin_token(token):
    key = f'admin_token:{token}'
    if not redis_client:
        return None
    val = redis_client.get(key)
    if val:
        redis_client.delete(key)
        return val.decode() if isinstance(val, bytes) else val
    return None

notify_queue = Queue()

def notification_worker():
    grouped = {}
    last_sent = time.time()
    while True:
        try:
            item = notify_queue.get(timeout=2)
            project_id, msg_text, recipients = item
            grouped.setdefault(project_id, {'texts': [], 'recipients': set()})
            grouped[project_id]['texts'].append(msg_text)
            grouped[project_id]['recipients'].update(recipients)
        except Empty:
            pass
        now = time.time()
        if now - last_sent >= 3 and grouped:
            for pid, payload in list(grouped.items()):
                summary = '\n'.join(payload['texts'][:5])
                body = f'Новые сообщения в проекте {pid}:\n{summary}'
                for r in list(payload['recipients'])[:100]:
                    try:
                        if bot:
                            bot.send_message(int(r), body)
                    except Exception:
                        logger.exception('Ошибка отправки уведомления')
            grouped.clear()
            last_sent = now

notif_thread = threading.Thread(target=notification_worker, daemon=True)
notif_thread.start()

def get_or_create_user(telegram_id, name=None):
    session = SessionLocal()
    try:
        u = session.query(User).filter_by(telegram_id=str(telegram_id)).first()
        if not u:
            role = session.query(Role).filter_by(name='user').first()
            u = User(telegram_id=str(telegram_id), name=name or '', role=role)
            session.add(u)
            session.commit()
        return u
    finally:
        session.close()

def user_is_admin(telegram_id):
    session = SessionLocal()
    try:
        u = session.query(User).filter_by(telegram_id=str(telegram_id)).first()
        return u and u.is_admin()
    finally:
        session.close()

# Telegram handlers
if bot:
    @bot.message_handler(commands=['start'])
    def cmd_start(message):
        uid = message.from_user.id
        get_or_create_user(uid, message.from_user.full_name)
        if APP_URL:
            import secrets
            # create short-lived web token bound to this telegram user
            st = secrets.token_urlsafe(16)
            # try to fetch user's profile photo and store a direct file URL
            photo_url = ''
            if bot:
                try:
                    photos = bot.get_user_profile_photos(uid)
                    if photos and getattr(photos, 'total_count', 0) > 0:
                        # take highest resolution of first photo
                        sizes = photos.photos[0]
                        file_obj = sizes[-1]
                        file_info = bot.get_file(file_obj.file_id)
                        photo_url = f'https://api.telegram.org/file/bot{BOT_TOKEN}/{file_info.file_path}'
                except Exception:
                    logger.exception('Не удалось получить фото профиля')
            if redis_client:
                # store minimal binding for web session
                redis_client.setex(f'web_st:{st}', 86400, json.dumps({'telegram_id': str(uid), 'photo_url': photo_url}))
            kb = types.InlineKeyboardMarkup()
            # Use Telegram Web App button to open inside Telegram client
            webinfo = types.WebAppInfo(f"{APP_URL}?st={st}")
            kb.add(types.InlineKeyboardButton('Открыть приложение', web_app=webinfo))
            bot.send_message(uid, 'Нажмите кнопку "Открыть приложение" — приложение откроется внутри Telegram.', reply_markup=kb)
        else:
            kb = types.ReplyKeyboardMarkup(row_width=2)
            kb.add('Проекты', 'Мой профиль')
            kb.add('Чаты', 'Помощь')
            bot.send_message(uid, 'Главное меню (веб-приложение не настроено).', reply_markup=kb)

    @bot.message_handler(func=lambda m: m.text == 'Проекты')
    def btn_projects(message):
        uid = message.from_user.id
        projs = get_projects_cached()
        for p in projs:
            text = f"{p['title']}\n{p['description'][:200]}"
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton('О проекте', callback_data=f'proj:{p["id"]}'))
            markup.add(types.InlineKeyboardButton('Прикрепиться', callback_data=f'join:{p["id"]}'))
            bot.send_message(uid, text, reply_markup=markup)

    @bot.callback_query_handler(func=lambda c: True)
    def callback_query(call):
        data = call.data
        uid = call.from_user.id
        if data.startswith('join:'):
            pid = int(data.split(':')[1])
            session = SessionLocal()
            try:
                user = get_or_create_user(uid, call.from_user.full_name)
                exists = session.query(Membership).filter_by(user_id=user.id, project_id=pid).first()
                if exists:
                    bot.answer_callback_query(call.id, 'Вы уже в проекте')
                else:
                    m = Membership(user_id=user.id, project_id=pid)
                    session.add(m); session.commit()
                    bot.answer_callback_query(call.id, 'Вы прикреплены к проекту')
            finally:
                session.close()
        elif data.startswith('leave:'):
            pid = int(data.split(':')[1])
            session = SessionLocal()
            try:
                user = session.query(User).filter_by(telegram_id=str(uid)).first()
                if not user:
                    bot.answer_callback_query(call.id, 'Не найден пользователь')
                    return
                session.query(Membership).filter_by(user_id=user.id, project_id=pid).delete(); session.commit()
                bot.answer_callback_query(call.id, 'Вы покинули проект')
            finally:
                session.close()
        elif data == 'admin_panel':
            token = generate_admin_token(uid)
            link = f"{APP_URL}/admin?token={token}"
            bot.send_message(uid, f'Ссылка в админ-панель (одноразовая, {ADMIN_TOKEN_TTL}s): {link}')

@app.route('/webhook', methods=['POST'])
def webhook():
    if not bot:
        return 'Bot not configured', 500
    try:
        json_str = request.get_data().decode('utf-8')
        update = types.Update.de_json(json.loads(json_str))
        bot.process_new_updates([update])
    except Exception:
        logger.exception('Ошибка обработки вебхука')
    return '', 200

@app.route('/set_webhook')
def set_webhook():
    if not bot:
        return 'Bot not configured', 500
    if not APP_URL:
        return 'APP_URL not set', 400
    res = bot.set_webhook(f"{APP_URL}/webhook")
    return jsonify({'ok': res})

# SPA
@app.route('/')
def index():
    return render_template('spa.html', bot_username=BOT_USERNAME, app_url=APP_URL)

@app.route('/api/projects')
def api_projects():
    projs = get_projects_cached()
    return jsonify(projs)


# WebApp initData validation helper and route
def validate_init_data(init_data: str, bot_token: str):
    """
    Validate Telegram WebApp initData (signed payload).
    Returns (valid: bool, params: dict).
    """
    try:
        if not init_data or not bot_token:
            return False, {}
        # parse query-string like payload
        params = dict(urllib.parse.parse_qsl(init_data, keep_blank_values=True))
        hash_val = params.pop('hash', None)
        if not hash_val:
            return False, params
        check_list = []
        for k in sorted(params.keys()):
            check_list.append(f"{k}={params[k]}")
        data_check_string = '\n'.join(check_list)
        secret_key = hashlib.sha256(bot_token.encode()).digest()
        hmac_value = hmac.new(secret_key, msg=data_check_string.encode(), digestmod=hashlib.sha256).hexdigest()
        valid = hmac.compare_digest(hmac_value, hash_val)
        return valid, params
    except Exception:
        logger.exception('validate_init_data error')
        return False, {}


@app.route('/webapp/init', methods=['POST'])
def webapp_init():
    """Accepts JSON { initData: string } from Telegram WebApp, validates signature,
    and tries to fetch user avatar via Bot API. Returns { ok, user, photo_url }.
    """
    payload = request.json or {}
    init_data = payload.get('initData') or ''
    ok, params = validate_init_data(init_data, BOT_TOKEN or '')
    if not ok:
        return jsonify({'ok': False, 'error': 'invalid initData'}), 403
    user = {}
    photo_url = params.get('photo_url') or ''
    try:
        # Telegram WebApp often sends `user` as a JSON-encoded string inside initData
        user_json = None
        if 'user' in params and params.get('user'):
            try:
                user_json = json.loads(params.get('user'))
            except Exception:
                user_json = None
        if user_json:
            uid_int = int(user_json.get('id')) if str(user_json.get('id') or '').isdigit() else None
            user['id'] = uid_int
            user['first_name'] = user_json.get('first_name')
            user['last_name'] = user_json.get('last_name')
            user['username'] = user_json.get('username')
            # sometimes photo_url can be inside user object
            if not photo_url:
                photo_url = user_json.get('photo_url') or ''
        else:
            uid = params.get('id') or params.get('user_id')
            uid_int = int(uid) if uid and str(uid).isdigit() else None
            user['id'] = uid_int
            user['first_name'] = params.get('first_name')
            user['last_name'] = params.get('last_name')
            user['username'] = params.get('username')
        user['full_name'] = ((user.get('first_name') or '') + (' ' + (user.get('last_name') or '') if user.get('last_name') else '')).strip()
        # If no photo_url supplied, try Bot API
        if not photo_url and bot and uid_int:
            try:
                photos = bot.get_user_profile_photos(uid_int)
                if photos and getattr(photos, 'total_count', 0) > 0:
                    sizes = photos.photos[0]
                    file_obj = sizes[-1]
                    file_info = bot.get_file(file_obj.file_id)
                    photo_url = f'https://api.telegram.org/file/bot{BOT_TOKEN}/{file_info.file_path}'
            except Exception:
                logger.exception('Не удалось получить фото профиля через Bot API (webapp/init)')
        # Mirror photo into DB (UserPhoto) to allow avatar API and caching
        try:
            if photo_url and uid_int is not None:
                dbp = SessionLocal()
                try:
                    existing = dbp.query(UserPhoto).get(int(uid_int))
                    now = datetime.utcnow()
                    if existing:
                        if existing.photo_url != photo_url:
                            existing.photo_url = photo_url
                            existing.updated_at = now
                            dbp.commit()
                    else:
                        dbp.add(UserPhoto(user_id=int(uid_int), photo_url=photo_url, updated_at=now)); dbp.commit()
                finally:
                    dbp.close()
        except Exception:
            logger.exception('Mirror user photo failed (webapp/init)')
        return jsonify({'ok': True, 'user': user, 'photo_url': photo_url})
    except Exception:
        logger.exception('webapp/init processing error')
        return jsonify({'ok': False, 'error': 'server_error'}), 500


@app.route('/profile')
def profile_page():
    return render_template('profile.html')

def require_admin_token():
    token = request.args.get('token')
    if not token or not redis_client:
        abort(403)
    tid = validate_admin_token(token)
    if not tid:
        abort(403)
    session = SessionLocal()
    try:
        u = session.query(User).filter_by(telegram_id=str(tid)).first()
        if not u or not u.is_admin():
            abort(403)
        return u
    finally:
        session.close()

@app.route('/admin')
def admin_index():
    user = require_admin_token()
    projs = get_projects_cached()
    return render_template('admin_index.html', projects=projs, token=request.args.get('token'))

@app.route('/admin/project/new', methods=['GET','POST'])
@app.route('/admin/project/<int:pid>', methods=['GET','POST','DELETE'])
def admin_project(pid=None):
    user = require_admin_token()
    session = SessionLocal()
    try:
        if request.method == 'POST':
            title = request.form.get('title')
            desc = request.form.get('description')
            main = request.form.get('main_photo_url')
            extra = request.form.get('extra_photos')
            if pid:
                p = session.query(Project).get(pid)
                p.title = title; p.description = desc; p.main_photo_url = main; p.extra_photos_json = extra
            else:
                p = Project(title=title, description=desc, main_photo_url=main, extra_photos_json=extra)
                session.add(p)
            session.commit()
            if redis_client:
                redis_client.delete(PROJECTS_CACHE_KEY)
            return redirect(f"/admin?token={request.args.get('token')}")
        if pid:
            p = session.query(Project).get(pid)
            if not p:
                abort(404)
            return render_template('admin_project_form.html', project=p, token=request.args.get('token'))
        else:
            return render_template('admin_project_form.html', project=None, token=request.args.get('token'))
    finally:
        session.close()

@app.route('/admin/project/<int:pid>/chat')
def admin_project_chat(pid):
    user = require_admin_token()
    session = SessionLocal()
    try:
        p = session.query(Project).get(pid)
        if not p:
            abort(404)
        return render_template('admin_chat.html', project=p, token=request.args.get('token'))
    finally:
        session.close()

@app.route('/auth/telegram', methods=['GET','POST'])
def auth_telegram():
    # GET: legacy redirect generator
    if request.method == 'GET':
        import secrets
        st = secrets.token_urlsafe(12)
        tid = request.args.get('telegram_id')
        if redis_client:
            redis_client.setex(f'web_st:{st}', 300, json.dumps({'telegram_id': tid or '', 'photo_url': ''}))
        return redirect(url_for('index') + f'?st={st}')
    # POST: validate Telegram Login widget data
    data = request.json or {}
    hash_received = data.pop('hash', None)
    if not hash_received:
        return jsonify({'error':'missing hash'}), 400
    import hmac, hashlib
    check_list = []
    for k in sorted(data.keys()):
        check_list.append(f"{k}={data[k]}")
    data_check_string = '\n'.join(check_list)
    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()
    hmac_value = hmac.new(secret_key, msg=data_check_string.encode(), digestmod=hashlib.sha256).hexdigest()
    if not hmac.compare_digest(hmac_value, hash_received):
        return jsonify({'error':'invalid signature'}), 403
    import secrets
    st = secrets.token_urlsafe(16)
    telegram_id = data.get('id')
    name = (data.get('first_name') or '') + ((' ' + data.get('last_name')) if data.get('last_name') else '')
    username = data.get('username') or ''
    photo_url = data.get('photo_url') or ''
    # Если photo_url не пришёл, пробуем получить через Bot API
    if not photo_url and bot and telegram_id:
        try:
            photos = bot.get_user_profile_photos(telegram_id)
            if photos and getattr(photos, 'total_count', 0) > 0:
                sizes = photos.photos[0]
                file_obj = sizes[-1]
                file_info = bot.get_file(file_obj.file_id)
                photo_url = f'https://api.telegram.org/file/bot{BOT_TOKEN}/{file_info.file_path}'
        except Exception:
            logger.exception('Не удалось получить фото профиля через Bot API')
    session = SessionLocal()
    try:
        u = session.query(User).filter_by(telegram_id=str(telegram_id)).first()
        if not u:
            role = session.query(Role).filter_by(name='user').first()
            u = User(telegram_id=str(telegram_id), name=name, role=role)
            session.add(u); session.commit()
        # Можно добавить сохранение username, если нужно
        if u and username and (not hasattr(u, 'username') or getattr(u, 'username', None) != username):
            try:
                setattr(u, 'username', username)
                session.commit()
            except Exception:
                pass
    finally:
        session.close()
    if redis_client:
        redis_client.setex(f'web_st:{st}', 86400, json.dumps({'telegram_id': str(telegram_id), 'photo_url': photo_url, 'username': username}))
    return jsonify({'ok': True, 'st': st})


@app.route('/api/me')
def api_me():
    st = request.args.get('st') or request.args.get('token')
    if not st or not redis_client:
        return jsonify({'error':'not authenticated'}), 401
    val = redis_client.get(f'web_st:{st}')
    if not val:
        logger.warning(f'Invalid or expired token: {st}')
        return jsonify({'error':'invalid token'}), 401
    raw = val.decode() if isinstance(val, bytes) else val
    try:
        obj = json.loads(raw)
    except Exception:
        obj = {'telegram_id': raw, 'photo_url': ''}
    tid = obj.get('telegram_id')
    photo = obj.get('photo_url')
    username = obj.get('username')
    if not tid:
        return jsonify({'error':'no telegram_id bound'}), 401
    session = SessionLocal()
    try:
        u = session.query(User).filter_by(telegram_id=str(tid)).first()
        if not u:
            return jsonify({'error':'user not found'}), 404
        # ensure first_seen timestamp is present in redis entry
        first_seen = obj.get('first_seen')
        if not first_seen and redis_client:
            first_seen = datetime.utcnow().isoformat()
            obj['first_seen'] = first_seen
            try:
                redis_client.setex(f'web_st:{st}', 86400, json.dumps(obj))
            except Exception:
                logger.exception('Не удалось обновить web_st с first_seen')
        # mirror photo into DB (UserPhoto) to allow avatar API and caching
        try:
            if photo:
                dbp = SessionLocal()
                try:
                    # store by numeric telegram id if possible
                    uid_int = int(tid) if str(tid).isdigit() else None
                    if uid_int is not None:
                        existing = dbp.query(UserPhoto).get(uid_int)
                        now = datetime.utcnow()
                        if existing:
                            if existing.photo_url != photo:
                                existing.photo_url = photo
                                existing.updated_at = now
                                dbp.commit()
                        else:
                            dbp.add(UserPhoto(user_id=uid_int, photo_url=photo, updated_at=now)); dbp.commit()
                finally:
                    dbp.close()
        except Exception:
            logger.exception('Mirror user photo failed')
        return jsonify({'telegram_id': u.telegram_id, 'name': u.name or '', 'photo_url': photo, 'first_seen': first_seen, 'username': username})
    finally:
        session.close()


@app.route('/api/user/avatars')
def api_user_avatars():
    ids_param = request.args.get('ids', '').strip()
    if not ids_param or SessionLocal is None:
        return jsonify({'avatars': {}})
    try:
        ids = [int(x) for x in ids_param.split(',') if x.strip().isdigit()]
    except Exception:
        ids = []
    if not ids:
        return jsonify({'avatars': {}})
    db = SessionLocal()
    try:
        rows = db.query(UserPhoto).filter(UserPhoto.user_id.in_(ids)).all()
        out = {}
        for r in rows:
            if r.photo_url:
                out[str(int(r.user_id))] = r.photo_url
        resp = jsonify({'avatars': out})
        resp.headers['Cache-Control'] = 'public, max-age=3600'
        return resp
    finally:
        db.close()

@app.route('/api/project/<int:pid>/message', methods=['POST'])
def api_send_message(pid):
    data = request.json or {}
    tid = data.get('telegram_id')
    text = data.get('text')
    if not tid or not text:
        return jsonify({'error': 'missing fields'}), 400
    session = SessionLocal()
    try:
        user = get_or_create_user(tid)
        m = Message(project_id=pid, user_id=user.id, text=text)
        session.add(m); session.commit()
        payload = {'id': m.id, 'project_id': pid, 'user': user.name or user.telegram_id, 'text': text, 'created_at': m.created_at.isoformat()}
        socketio.emit('message', payload, room=f'project_{pid}')
        members = session.query(Membership).filter_by(project_id=pid).all()
        recipients = {session.query(User).get(mem.user_id).telegram_id for mem in members}
        notify_queue.put((pid, text, recipients))
        return jsonify({'ok': True, 'message': payload})
    finally:
        session.close()


def parse_mentions(text):
    # simple mentions: @123456 (telegram id) or @username (not resolved here)
    if not text:
        return set()
    import re
    ids = set()
    for m in re.findall(r'@([0-9]{5,})', text):
        ids.add(m)
    return ids


@app.route('/api/project/<int:pid>/activities')
def api_get_activities(pid):
    limit = int(request.args.get('limit', 50))
    session = SessionLocal()
    try:
        acts = session.query(Activity).filter_by(project_id=pid).order_by(Activity.created_at.desc()).limit(limit).all()
        out = []
        for a in acts:
            out.append({'id': a.id, 'type': a.type, 'text': a.text, 'metadata': json.loads(a.metadata or '{}') if a.metadata else {}, 'actor': (a.actor.name if a.actor else None), 'created_at': a.created_at.isoformat()})
        return jsonify(out)
    finally:
        session.close()


@app.route('/api/project/<int:pid>/activity', methods=['POST'])
def api_create_activity(pid):
    data = request.json or {}
    actor_tid = data.get('telegram_id')
    text = data.get('text')
    typ = data.get('type', 'note')
    meta = data.get('metadata') or {}
    session = SessionLocal()
    try:
        actor = None
        if actor_tid:
            actor = get_or_create_user(actor_tid)
        a = Activity(project_id=pid, actor_user_id=(actor.id if actor else None), type=typ, text=text, metadata=json.dumps(meta))
        session.add(a); session.commit()
        payload = {'id': a.id, 'project_id': pid, 'type': a.type, 'text': a.text, 'actor': actor.name if actor else None, 'created_at': a.created_at.isoformat()}
        socketio.emit('activity', payload, room=f'project_{pid}')
        # mention notifications
        mentions = parse_mentions(text)
        if mentions:
            notify_queue.put((pid, f'Упоминание в проекте {pid}: {text[:120]}', mentions))
        # also notify project members
        members = session.query(Membership).filter_by(project_id=pid).all()
        recipients = {session.query(User).get(mem.user_id).telegram_id for mem in members}
        notify_queue.put((pid, text, recipients))
        return jsonify({'ok': True, 'activity': payload})
    finally:
        session.close()


@app.route('/api/activity/<int:aid>/comment', methods=['POST'])
def api_create_comment(aid):
    data = request.json or {}
    tid = data.get('telegram_id')
    text = data.get('text')
    if not text or not tid:
        return jsonify({'error': 'missing fields'}), 400
    session = SessionLocal()
    try:
        a = session.query(Activity).get(aid)
        if not a:
            return jsonify({'error': 'activity not found'}), 404
        user = get_or_create_user(tid)
        c = ActivityComment(activity_id=aid, user_id=user.id, text=text)
        session.add(c); session.commit()
        payload = {'id': c.id, 'activity_id': aid, 'user': user.name, 'text': text, 'created_at': c.created_at.isoformat()}
        socketio.emit('activity_comment', payload, room=f'project_{a.project_id}')
        # mentions
        mentions = parse_mentions(text)
        if mentions:
            notify_queue.put((a.project_id, f'Упоминание в комментарии проекта {a.project_id}: {text[:120]}', mentions))
        return jsonify({'ok': True, 'comment': payload})
    finally:
        session.close()


@app.route('/api/project/<int:pid>/tasks', methods=['GET','POST'])
def api_tasks(pid):
    session = SessionLocal()
    try:
        if request.method == 'GET':
            tasks = session.query(Task).filter_by(project_id=pid).order_by(Task.created_at.asc()).all()
            out = [{'id': t.id, 'title': t.title, 'status': t.status, 'assignee_id': (t.assignee.telegram_id if t.assignee else None), 'created_at': t.created_at.isoformat()} for t in tasks]
            return jsonify(out)
        else:
            data = request.json or {}
            title = data.get('title')
            assignee_tid = data.get('assignee_telegram_id')
            if not title:
                return jsonify({'error':'missing title'}), 400
            assignee = None
            if assignee_tid:
                assignee = get_or_create_user(assignee_tid)
            t = Task(project_id=pid, title=title, assignee_id=(assignee.id if assignee else None))
            session.add(t); session.commit()
            payload = {'id': t.id, 'title': t.title, 'status': t.status, 'assignee_id': (assignee.telegram_id if assignee else None), 'created_at': t.created_at.isoformat()}
            socketio.emit('task_created', payload, room=f'project_{pid}')
            # add an activity entry
            a = Activity(project_id=pid, actor_user_id=(assignee.id if assignee else None), type='task_created', text=f'Task: {title}', metadata=json.dumps({'task_id': t.id}))
            session.add(a); session.commit()
            # notify members
            members = session.query(Membership).filter_by(project_id=pid).all()
            recipients = {session.query(User).get(mem.user_id).telegram_id for mem in members}
            notify_queue.put((pid, f'Новая задача в проекте {pid}: {title}', recipients))
            return jsonify({'ok': True, 'task': payload})
    finally:
        session.close()


@app.route('/api/task/<int:tid>', methods=['POST'])
def api_update_task(tid):
    data = request.json or {}
    status = data.get('status')
    assignee_tid = data.get('assignee_telegram_id')
    session = SessionLocal()
    try:
        t = session.query(Task).get(tid)
        if not t:
            return jsonify({'error':'not found'}), 404
        if status:
            t.status = status
        if assignee_tid:
            assignee = get_or_create_user(assignee_tid)
            t.assignee_id = assignee.id
        session.commit()
        payload = {'id': t.id, 'title': t.title, 'status': t.status, 'assignee_id': (t.assignee.telegram_id if t.assignee else None)}
        socketio.emit('task_updated', payload, room=f'project_{t.project_id}')
        # activity log
        a = Activity(project_id=t.project_id, actor_user_id=(t.assignee_id if t.assignee_id else None), type='task_updated', text=f'Task updated: {t.title}', metadata=json.dumps({'task_id': t.id}))
        session.add(a); session.commit()
        # notify members
        members = session.query(Membership).filter_by(project_id=t.project_id).all()
        recipients = {session.query(User).get(mem.user_id).telegram_id for mem in members}
        notify_queue.put((t.project_id, f'Задача обновлена: {t.title}', recipients))
        return jsonify({'ok': True, 'task': payload})
    finally:
        session.close()

@app.route('/api/project/<int:pid>/messages')
def api_get_messages(pid):
    last_id = int(request.args.get('after', 0))
    session = SessionLocal()
    try:
        msgs = session.query(Message).filter(Message.project_id==pid, Message.id>last_id).order_by(Message.id.asc()).all()
        out = [{'id': m.id, 'user': m.user.name or m.user.telegram_id, 'text': m.text, 'created_at': m.created_at.isoformat()} for m in msgs]
        return jsonify(out)
    finally:
        session.close()

@socketio.on('join')
def on_join(data):
    pid = data.get('project_id')
    join_room(f'project_{pid}')

@socketio.on('leave')
def on_leave(data):
    pid = data.get('project_id')
    leave_room(f'project_{pid}')

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    if bot and APP_URL:
        try:
            bot.remove_webhook()
            bot.set_webhook(f"{APP_URL}/webhook")
            logger.info('Webhook установлен')
        except Exception:
            logger.exception('Не удалось установить webhook')
    allow_unsafe = os.getenv('ALLOW_UNSAFE_WERKZEUG', '0') == '1'
    if allow_unsafe:
        logger.warning('Запуск с allow_unsafe_werkzeug=True. Это не безопасно для production.')
        socketio.run(app, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
    else:
        socketio.run(app, host='0.0.0.0', port=port)
