"""
Инструкция по деплою на Render (коротко, только переменные):

Переменные окружения, необходимые на Render:
- BOT_TOKEN = токен Telegram-бота (начинается с 123...)
- DATABASE_URL = SQLAlchemy URL для Postgres (пример: postgresql://user:pass@host:5432/dbname)
- REDIS_URL = URL Redis (пример: redis://:password@host:6379/0)
- OWNER_TELEGRAM_ID = Telegram user_id владельца (int)
- INITIAL_ADMINS = CSV списка telegram user_id для начальных админов (например: 12345,67890)
- APP_URL = публичный URL приложения на Render (https://your-app.onrender.com)

Этот файл — единый рабочий Flask-приложение с Telegram webhook, встроенной веб-панелью
и простыми проектными чатами. Шаблоны Jinja2 упакованы как строковые переменные ниже.

Примечание: не храните секреты в коде; используйте переменные окружения в Render.
"""

import os
import json
import time
import threading
from queue import Queue, Empty
from datetime import datetime
from urllib.parse import urlencode

from flask import Flask, request, redirect, url_for, abort, render_template_string, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import telebot
from telebot import types
from sqlalchemy import (create_engine, Column, Integer, String, Text, DateTime, ForeignKey)
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
import redis
import logging

# --- Конфигурация и инициализация ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Загружаемые переменные окружения (Render)
BOT_TOKEN = os.getenv('BOT_TOKEN')
DATABASE_URL = os.getenv('DATABASE_URL')
REDIS_URL = os.getenv('REDIS_URL')
OWNER_TELEGRAM_ID = os.getenv('OWNER_TELEGRAM_ID')
INITIAL_ADMINS = os.getenv('INITIAL_ADMINS', '')  # CSV
APP_URL = os.getenv('APP_URL')  # https://your-app.onrender.com

if not BOT_TOKEN or not DATABASE_URL or not REDIS_URL or not OWNER_TELEGRAM_ID or not APP_URL:
    logger.warning('Некоторые переменные окружения не заданы: BOT_TOKEN, DATABASE_URL, REDIS_URL, OWNER_TELEGRAM_ID, APP_URL являются обязательными')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET', 'change_me_in_prod')

# SocketIO с Redis message queue для масштабирования
socketio = SocketIO(app, cors_allowed_origins='*', message_queue=REDIS_URL, async_mode='threading')

# TeleBot (не используем long-polling; only webhooks)
bot = telebot.TeleBot(BOT_TOKEN) if BOT_TOKEN else None

# Redis client
redis_client = redis.from_url(REDIS_URL) if REDIS_URL else None

# SQLAlchemy setup
Base = declarative_base()
engine = create_engine(DATABASE_URL or 'sqlite:///data.db', echo=False, future=True)
SessionLocal = sessionmaker(bind=engine)

# --- Модели ---
class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), unique=True, nullable=False)  # owner, admin, worker, user

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
    extra_photos_json = Column(Text)  # JSON list of URLs
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

# --- Инициализация БД и ролей/первых пользователей ---
def init_db():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        # Ensure roles
        for r in ('owner', 'admin', 'worker', 'user'):
            if not session.query(Role).filter_by(name=r).first():
                session.add(Role(name=r))
        session.commit()

        # Owner from env
        owner_tid = str(OWNER_TELEGRAM_ID) if OWNER_TELEGRAM_ID else None
        if owner_tid:
            owner = session.query(User).filter_by(telegram_id=owner_tid).first()
            owner_role = session.query(Role).filter_by(name='owner').first()
            if not owner:
                owner = User(telegram_id=owner_tid, name='Owner', role=owner_role)
                session.add(owner)
        # Initial admins
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

# --- Кэш проектов в Redis ---
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
        lst = json.loads(data)
        # reconstruct lightweight dicts
        return lst
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

# --- Админ-токены (одноразовые) ---
ADMIN_TOKEN_TTL = 300  # seconds

def generate_admin_token(telegram_id):
    import secrets
    token = secrets.token_urlsafe(16)
    key = f'admin_token:{token}'
    redis_client.setex(key, ADMIN_TOKEN_TTL, str(telegram_id))
    return token

def validate_admin_token(token):
    key = f'admin_token:{token}'
    val = redis_client.get(key)
    if val:
        # consume
        redis_client.delete(key)
        return val.decode() if isinstance(val, bytes) else val
    return None

# --- Уведомления в Telegram: очередь и фоновая отправка с простым rate-limit ---
notify_queue = Queue()

def notification_worker():
    """Фоновый воркер группирует уведомления по проекту и шлет каждые 3 секунды"""
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
                    except Exception as e:
                        logger.exception('Ошибка отправки уведомления')
            grouped.clear()
            last_sent = now

notif_thread = threading.Thread(target=notification_worker, daemon=True)
notif_thread.start()

# --- Помощники работы с DB / пользователями ---
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

# --- Telegram handlers (webhook) ---
if bot:
    @bot.message_handler(commands=['start'])
    def cmd_start(message):
        uid = message.from_user.id
        get_or_create_user(uid, message.from_user.full_name)
        kb = types.ReplyKeyboardMarkup(row_width=2)
        kb.add('Проекты', 'Мой профиль')
        kb.add('Чаты', 'Помощь')
        bot.send_message(uid, 'Главное меню', reply_markup=kb)

    @bot.message_handler(func=lambda m: m.text == 'Проекты')
    def btn_projects(message):
        uid = message.from_user.id
        projs = get_projects_cached()
        for p in projs:
            text = f"{p['title']}\n{p['description'][:200]}"
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton('О проекте', callback_data=f'proj:{p['id']}'))
            markup.add(types.InlineKeyboardButton('Прикрепиться', callback_data=f'join:{p['id']}'))
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
                    # notify
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
            # generate admin token and send link
            token = generate_admin_token(uid)
            link = f"{APP_URL}/admin?token={token}"
            bot.send_message(uid, f'Ссылка в админ-панель (одноразовая, {ADMIN_TOKEN_TTL}s): {link}')

# Webhook endpoint for Telegram
@app.route('/webhook', methods=['POST'])
def webhook():
    if not bot:
        return 'Bot not configured', 500
    try:
        json_str = request.get_data().decode('utf-8')
        update = types.Update.de_json(json.loads(json_str))
        bot.process_new_updates([update])
    except Exception as e:
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

# --- Веб-панель (admin) ---
# Шаблоны упакованы как строки
base_template = '''
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin - Панель</title>
  <link rel="stylesheet" href="/static/css/style.css">
  <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
  <script src="/static/js/main.js"></script>
</head>
<body>
<div class="container">
  <header><h1>Панель управления</h1></header>
  <main>
    {% block content %}{% endblock %}
  </main>
  <footer>Бот каркас — панель администрирования</footer>
</div>
</body>
</html>
'''

admin_index_template = '''{% extends 'base' %}
{% block content %}
<h2>Проекты</h2>
<a href="/admin/project/new?token={{ token }}">Создать проект</a>
<ul>
  {% for p in projects %}
    <li>
      <strong>{{ p.title }}</strong> — {{ p.description[:120] }}
      [<a href="/admin/project/{{ p.id }}?token={{ token }}">Ред.</a>]
      [<a href="/admin/project/{{ p.id }}/chat?token={{ token }}">Чат</a>]
    </li>
  {% endfor %}
</ul>
{% endblock %}
'''

admin_project_form = '''{% extends 'base' %}
{% block content %}
<h2>{{ 'Создать' if not project else 'Редактировать' }} проект</h2>
<form method="post">
  <label>Заголовок: <input name="title" value="{{ project.title if project else '' }}"></label><br>
  <label>Описание:<br><textarea name="description">{{ project.description if project else '' }}</textarea></label><br>
  <label>Фото (main url): <input name="main_photo_url" value="{{ project.main_photo_url if project else '' }}"></label><br>
  <label>Доп. фото (JSON array):<br><textarea name="extra_photos">{{ project.extra_photos if project else '[]' }}</textarea></label><br>
  <button type="submit">Сохранить</button>
</form>
{% endblock %}
'''

admin_chat_template = '''{% extends 'base' %}
{% block content %}
<h2>Чат проекта: {{ project.title }}</h2>
<div id="chat" data-project-id="{{ project.id }}">
  <div id="messages"></div>
  <form id="msgform">
    <input id="msgtext" placeholder="Сообщение...">
    <button>Отправить</button>
  </form>
</div>
<script>
  // JS клиент реализован в static/js/main.js — использует SocketIO, fallback polling каждые 60s
</script>
{% endblock %}
'''

# Flask-шаблон-воркера: используем render_template_string и передаём base
def render(tpl, **ctx):
    # register base as a template for extending
    templates = {'base': base_template}
    templates.update({ 'tpl': tpl })
    # Jinja allows us to set loader, но для простоты — use render_template_string with inheritance trick
    full = tpl
    return render_template_string(full, **ctx)

def require_admin_token():
    token = request.args.get('token')
    if not token or not redis_client:
        abort(403)
    tid = validate_admin_token(token)
    if not tid:
        abort(403)
    # ensure user is admin in DB
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
    return render(admin_index_template, projects=projs, token=request.args.get('token'))

@app.route('/admin/project/new', methods=['GET', 'POST'])
@app.route('/admin/project/<int:pid>', methods=['GET', 'POST', 'DELETE'])
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
            # invalidate cache
            if redis_client:
                redis_client.delete(PROJECTS_CACHE_KEY)
            return redirect(f"/admin?token={request.args.get('token')}")
        if pid:
            p = session.query(Project).get(pid)
            if not p:
                abort(404)
            return render(admin_project_form, project=p, token=request.args.get('token'))
        else:
            return render(admin_project_form, project=None, token=request.args.get('token'))
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
        return render(admin_chat_template, project=p, token=request.args.get('token'))
    finally:
        session.close()

# REST API: отправить сообщение в проектный чат (веб-панель)
@app.route('/api/project/<int:pid>/message', methods=['POST'])
def api_send_message(pid):
    # expects json {telegram_id, text}
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
        # broadcast via socketio
        payload = {'id': m.id, 'project_id': pid, 'user': user.name or user.telegram_id, 'text': text, 'created_at': m.created_at.isoformat()}
        socketio.emit('message', payload, room=f'project_{pid}')
        # enqueue notifications to project participants
        members = session.query(Membership).filter_by(project_id=pid).all()
        recipients = {session.query(User).get(mem.user_id).telegram_id for mem in members}
        # include owner and admins who are in project? owner maybe not explicitly
        notify_queue.put((pid, text, recipients))
        return jsonify({'ok': True, 'message': payload})
    finally:
        session.close()

# Polling endpoint: возвращает новые сообщения после last_id
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

# SocketIO handlers
@socketio.on('join')
def on_join(data):
    pid = data.get('project_id')
    join_room(f'project_{pid}')

@socketio.on('leave')
def on_leave(data):
    pid = data.get('project_id')
    leave_room(f'project_{pid}')

# --- Статичные файлы и минимальные ассеты будут в папке static/ ---

if __name__ == '__main__':
    # локальный запуск (render будет запускать через gunicorn или web process)
    port = int(os.getenv('PORT', 5000))
    # при старте можно автоматически установить webhook (если APP_URL задан)
    if bot and APP_URL:
        try:
            bot.remove_webhook()
            bot.set_webhook(f"{APP_URL}/webhook")
            logger.info('Webhook установлен')
        except Exception as e:
            logger.exception('Не удалось установить webhook')
    socketio.run(app, host='0.0.0.0', port=port)
