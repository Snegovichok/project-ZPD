import os
import datetime
import eventlet

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_socketio import SocketIO, join_room, emit
from flask_wtf import CSRFProtect
from flask_talisman import Talisman

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from eventlet import wsgi

# Загрузка настроек из переменных окружения
SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback_secret_key')
DATABASE_URI = os.environ.get('DATABASE_URI', 'sqlite:///site.db')
UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # Максимальный размер загрузки файла 100 МБ

# В продакшене включите все COOKIE
app.config['SESSION_COOKIE_SECURE'] = False #True
app.config['REMEMBER_COOKIE_SECURE'] = False #True
app.config['SESSION_COOKIE_HTTPONLY'] = True

# CSRF-защита
csrf = CSRFProtect(app)
# Заголовки безопасности через Flask-Talisman
talisman = Talisman(app, content_security_policy={
    'default-src': ["'self'"],
    'script-src': ["'self'", 'https://cdnjs.cloudflare.com'], #"'unsafe-inline'" отключить безопасность
    'style-src': ["'self'", 'https://fonts.googleapis.com'],
    'font-src': ["'self'", 'https://fonts.gstatic.com']
})

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'
socketio = SocketIO(app, async_mode='eventlet', manage_session=False)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Модели базы данных

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    room = db.Column(db.String(50), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    stored_filename = db.Column(db.String(200), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    size = db.Column(db.Integer)  # Добавляем поле для размера файла

    def update_size(self):
        # Рассчитываем размер файла после его загрузки
        self.size = os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], self.stored_filename))
        db.session.commit()

class PrivateChat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.String(6), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    creator_id = db.Column(db.Integer, nullable=False)
    created_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Flag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    flag_id = db.Column(db.String(64), unique=True, nullable=False)
    flag = db.Column(db.String(100), nullable=False)
    vuln = db.Column(db.Integer, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Основные маршруты

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for('account'))
    flash("Неверное имя пользователя или пароль")
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash("Пользователь уже существует")
            return redirect(url_for('register'))
        hashed = generate_password_hash(password)
        new_user = User(username=username, password=hashed)
        db.session.add(new_user)
        db.session.commit()
        flash("Регистрация успешна")
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/chat')
def chat():
    messages = Message.query.filter_by(room='general').order_by(Message.timestamp).all()
    return render_template('chat.html', messages=messages)

@app.route('/account')
@login_required
def account():
    return render_template('account.html')

@app.route('/files', methods=['GET', 'POST'])
@login_required
def files():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("Нет файла")
            return redirect(url_for('files'))
        file = request.files['file']
        if file.filename == '':
            flash("Файл не выбран")
            return redirect(url_for('files'))
        filename = secure_filename(file.filename)
        stored_filename = f"{current_user.id}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
        file.save(filepath)
        new_file = File(user_id=current_user.id, filename=filename, stored_filename=stored_filename)
        new_file.update_size()  # Обновляем размер файла
        db.session.add(new_file)
        db.session.commit()
        flash("Файл загружен")
        return redirect(url_for('files'))
    user_files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('files.html', files=user_files)

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        flash("Нет доступа к файлу")
        return redirect(url_for('files'))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.stored_filename)
    if not file_path.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        flash("Неверный путь к файлу")
        return redirect(url_for('files'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], file.stored_filename, as_attachment=True, download_name=file.filename)

@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        flash("Нет прав для удаления файла")
        return redirect(url_for('files'))
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.stored_filename))
    except Exception:
        pass
    db.session.delete(file)
    db.session.commit()
    flash("Файл удален")
    return redirect(url_for('files'))

@app.route('/create_private_chat', methods=['GET', 'POST'])
@login_required
def create_private_chat():
    chats = PrivateChat.query.filter_by(creator_id=current_user.id).all()
    if request.method == 'POST':
        password = request.form.get('password')
        if not password:
            flash("Введите пароль")
            return redirect(url_for('create_private_chat'))
        # Генерация уникального chat_id
        num = 1
        while True:
            chat_id = f"{num:06d}"
            if not PrivateChat.query.filter_by(chat_id=chat_id).first():
                break
            num += 1
        hashed = generate_password_hash(password)
        new_chat = PrivateChat(chat_id=chat_id, password=hashed, creator_id=current_user.id)
        db.session.add(new_chat)
        db.session.commit()
        flash(f"Приватный чат создан с ID: {chat_id}")
        return redirect(url_for('create_private_chat'))
    return render_template('create_private_chat.html', chats=chats)

@app.route('/delete_chat/<int:chat_db_id>', methods=['POST'])
@login_required
def delete_chat(chat_db_id):
    chat = PrivateChat.query.get_or_404(chat_db_id)
    if chat.creator_id != current_user.id:
        flash("Нет прав для удаления чата")
        return redirect(url_for('create_private_chat'))
    try:
        Message.query.filter_by(room=chat.chat_id).delete()
        db.session.delete(chat)
        db.session.commit()
        socketio.emit('chat_deleted', {'chat_id': chat.chat_id}, room=chat.chat_id)
        flash("Чат удален")
    except Exception as e:
        db.session.rollback()
        flash("Ошибка при удалении чата")
    return redirect(url_for('create_private_chat'))

@app.route('/remove_joined_chat', methods=['POST'])
@login_required
def remove_joined_chat():
    chat_id = request.json.get('chat_id')
    if 'joined_chats' in session and chat_id in session['joined_chats']:
        session['joined_chats'].remove(chat_id)
        session.modified = True
    return '', 204

@app.route('/join_private_chat', methods=['GET', 'POST'])
@login_required
def join_private_chat():
    if request.method == 'POST':
        chat_id = request.form.get('chat_id')
        password = request.form.get('password')
        chat = PrivateChat.query.filter_by(chat_id=chat_id).first()
        if chat and check_password_hash(chat.password, password):
            if 'joined_chats' not in session:
                session['joined_chats'] = []
            if chat_id not in session['joined_chats']:
                session['joined_chats'].append(chat_id)
            flash("Подключение успешно")
            return redirect(url_for('private_chat', chat_id=chat_id))
        flash("Неверный ID или пароль")
    return render_template('join_private_chat.html')

@app.route('/private_chat/<chat_id>')
@login_required
def private_chat(chat_id):
    chat = PrivateChat.query.filter_by(chat_id=chat_id).first()
    if not chat:
        flash("Чат не существует или был удален")
        return redirect(url_for('join_private_chat'))
    if 'joined_chats' not in session or chat_id not in session['joined_chats']:
        flash("Вы не подключены к этому чату")
        return redirect(url_for('join_private_chat'))
    messages = Message.query.filter_by(room=chat_id).order_by(Message.timestamp).all()
    return render_template('private_chat.html', messages=messages, chat_id=chat_id)

# API для работы с флагами (используется чекером)
# В разработке
@app.route('/api/flag/put', methods=['POST'])
@csrf.exempt
def api_flag_put():
    data = request.json
    flag_id = data.get('flag_id')
    flag = data.get('flag')
    vuln = data.get('vuln')
    if not flag_id or not flag or vuln is None:
        return "Missing parameters", 400
    new_flag = Flag(flag_id=flag_id, flag=flag, vuln=int(vuln))
    db.session.add(new_flag)
    db.session.commit()
    response = app.response_class(response=flag, status=200)
    response.headers["X-New-Flag-ID"] = flag_id
    return response

@app.route('/api/flag/get', methods=['GET'])
@csrf.exempt
def api_flag_get():
    flag_id = request.args.get('flag_id')
    flag = request.args.get('flag')
    vuln = request.args.get('vuln')
    if not flag_id or not flag or vuln is None:
        return "Missing parameters", 400
    stored = Flag.query.filter_by(flag_id=flag_id, vuln=int(vuln)).first()
    if stored and stored.flag == flag:
        return "OK", 200
    return "Not found", 404

@app.route('/api/flag/delete', methods=['DELETE'])
@csrf.exempt
def api_flag_delete():
    data = request.json
    flag_id = data.get('flag_id')
    vuln = data.get('vuln')
    if not flag_id or vuln is None:
        return "Missing parameters", 400
    flag = Flag.query.filter_by(flag_id=flag_id, vuln=int(vuln)).first()
    if flag:
        db.session.delete(flag)
        db.session.commit()
        return "Deleted successfully", 200
    return "Flag not found", 404

@app.route('/api/flag/update', methods=['PUT'])
@csrf.exempt
def api_flag_update():
    data = request.json
    flag_id = data.get('flag_id')
    flag = data.get('flag')
    vuln = data.get('vuln')
    if not flag_id or not flag or vuln is None:
        return "Missing parameters", 400
    stored_flag = Flag.query.filter_by(flag_id=flag_id, vuln=int(vuln)).first()
    if stored_flag:
        stored_flag.flag = flag
        db.session.commit()
        return "Updated successfully", 200
    return "Flag not found", 404

@app.route('/api/flags/get_all', methods=['GET'])
@csrf.exempt
def api_flags_get_all():
    vuln = request.args.get('vuln')
    if vuln is None:
        return "Missing parameters", 400
    flags = Flag.query.filter_by(vuln=int(vuln)).all()
    if flags:
        return jsonify([{"flag_id": f.flag_id, "flag": f.flag} for f in flags]), 200
    return "No flags found", 404

@app.route('/api/flags/get_by_id', methods=['GET'])
@csrf.exempt
def api_flags_get_by_id():
    flag_id = request.args.get('flag_id')
    if not flag_id:
        return "Missing parameters", 400
    flags = Flag.query.filter_by(flag_id=flag_id).all()
    if flags:
        return jsonify([{"vuln": f.vuln, "flag": f.flag} for f in flags]), 200
    return "No flags found", 404

# Обработка событий SocketIO

@socketio.on('join')
def handle_join(data):
    room = data.get('room')
    join_room(room)
    emit('status', {'msg': f"{data.get('username')} присоединился к чату."}, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    room = data.get('room')
    username = data.get('username')
    message = data.get('message')
    new_msg = Message(user=username, content=message, room=room)
    db.session.add(new_msg)
    db.session.commit()
    emit('message', {'username': username, 'message': message}, room=room)

# Различные коды ошибок

@app.errorhandler(413)
def file_too_large(error):
    flash("Файл слишком большой! Максимальный размер файла: 100 МБ.")
    return redirect(url_for('files'))
'''
В разработке
    
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500
'''

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # В продакшене отключите debug-режим
    socketio.run(app, host='0.0.0.0', port=5000, debug=True) #False

