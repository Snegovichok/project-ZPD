#!/usr/bin/env python3

import sys
import requests
from bs4 import BeautifulSoup
import os
import time
import socketio
import json
import random
import string
import secrets

# Настройки
REQUEST_TIMEOUT = 5
SOCKETIO_TIMEOUT = 3
MAX_RETRIES = 1

# Адрес сервиса (будет переопределен при вызове)
BASE_URL = "http://localhost:5000"

def generate_flag(service_name):
    """Генерация тестового флага"""
    alph = string.ascii_uppercase + string.digits
    return service_name[0].upper() + ''.join(random.choices(alph, k=30)) + '='

def get_csrf_token(html):
    """Извлекает CSRF-токен из HTML-страницы."""
    soup = BeautifulSoup(html, "html.parser")
    token_tag = soup.find("input", {"name": "csrf_token"})
    return token_tag.get("value") if token_tag else None

def generate_random_username(prefix="checker_user_", length=6):
    """Генерация случайного логина с префиксом."""
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    return prefix + suffix
    
def generate_random_password_username(length=20, use_upper=True, use_lower=True, use_digits=True, use_special_chars=True, min_upper=1, min_lower=1, min_digits=1, min_special=1):
    """
    Генерация сложного случайного пароля или логина с заданными требованиями.

    Параметры:
    1. length (int): Длина пароля.
    2. use_upper (bool): Использовать заглавные буквы (A-Z).
    3. use_lower (bool): Использовать строчные буквы (a-z).
    4. use_digits (bool): Использовать цифры (0-9).
    5. use_special_chars (bool): Использовать спецсимволы (!@#$%^&*()_+ и т.д.).
    6. min_upper (int): Минимальное количество заглавных букв.
    7. min_lower (int): Минимальное количество строчных букв.
    8. min_digits (int): Минимальное количество цифр.
    9. min_special (int): Минимальное количество спецсимволов.
    """
    if length < (min_upper + min_lower + min_digits + min_special):
        raise ValueError("Длина пароля слишком мала для заданных ограничений!")

    chars = ""
    if use_upper:
        chars += string.ascii_uppercase
    if use_lower:
        chars += string.ascii_lowercase
    if use_digits:
        chars += string.digits
    if use_special_chars:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if not chars:
        raise ValueError("Не выбрано ни одного типа символов!")

    password = []
    
    # Добавляем обязательные символы
    if use_upper:
        password.extend(secrets.choice(string.ascii_uppercase) for _ in range(min_upper))
    if use_lower:
        password.extend(secrets.choice(string.ascii_lowercase) for _ in range(min_lower))
    if use_digits:
        password.extend(secrets.choice(string.digits) for _ in range(min_digits))
    if use_special_chars:
        password.extend(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?") for _ in range(min_special))

    # Заполняем оставшиеся символы случайными значениями
    remaining_length = length - len(password)
    password.extend(secrets.choice(chars) for _ in range(remaining_length))

    # Перемешиваем символы, чтобы обязательные не шли подряд
    random.shuffle(password)

    return ''.join(password)

def register(session):
    """Регистрирует пользователя с уникальным логином."""
    for attempt in range(MAX_RETRIES):
        try:
            url = f"{BASE_URL}/register"
            response = session.get(url, timeout=REQUEST_TIMEOUT)
            token = get_csrf_token(response.text)

            username = generate_random_username()
            password = generate_random_password_username()

            data = {
                "username": username,
                "password": password,
                "csrf_token": token
            }

            response = session.post(
                url,
                data=data,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT
            )

            if response.status_code == 200:
                print(f"[INFO] Registered as {username}")
                print(f"[INFO] Registered as {password}")
                return username, password  # возвращаем для логина

        except requests.exceptions.RequestException:
            if attempt == MAX_RETRIES - 1:
                return None, None

    return None, None

def login(session, username, password):
    """Авторизует пользователя."""
    for attempt in range(MAX_RETRIES):
        try:
            url = f"{BASE_URL}/"
            response = session.get(url, timeout=REQUEST_TIMEOUT)
            token = get_csrf_token(response.text)
            
            data = {
                "username": username,
                "password": password,
                "csrf_token": token
            }
            
            response = session.post(
                f"{BASE_URL}/login",
                data=data,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT
            )
            
            return response.status_code == 200
        except requests.exceptions.RequestException:
            if attempt == MAX_RETRIES - 1:
                return False

def send_chat_message(session, message, username):
    """Отправляет сообщение в чат через SocketIO без избыточной задержки."""
    for attempt in range(MAX_RETRIES):
        try:
            sio = socketio.Client()
            cookies = session.cookies.get_dict()
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()]) #

            received = {"ok": False}

            @sio.on("message")
            def on_message(data):
                if data.get("message") == message and data.get("username") == username:
                    received["ok"] = True
                    sio.disconnect()  # отключаемся сразу после получения ответа

            sio.connect(
                BASE_URL,
                headers={'Cookie': cookie_str},
                wait_timeout=SOCKETIO_TIMEOUT
            )

            sio.emit("join", {"room": "general", "username": username})
            sio.emit("send_message", {
                "room": "general",
                "username": username,
                "message": message
            })

            # ждем максимум 0.5 сек, чтобы не задерживаться
            start_time = time.time()
            while time.time() - start_time < 0.5:
                sio.sleep(0.05)
                if received["ok"]:
                    break

            if sio.connected:
                sio.disconnect()

            return received["ok"]

        except Exception as e:
            print(f"SocketIO error (attempt {attempt+1}): {str(e)}", file=sys.stderr)
            if attempt == MAX_RETRIES - 1:
                return False
            time.sleep(0.2)


def test_flag_put(session, flag_id, flag, vuln):
    """Тестирует сохранение флага."""
    for attempt in range(MAX_RETRIES):
        try:
            response = session.post(
                f"{BASE_URL}/api/flag/put",
                json={
                    "flag_id": flag_id,
                    "flag": flag,
                    "vuln": vuln
                },
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                print(f"[{time.ctime()}] PUT success", file=sys.stdout)  # Добавлено
                return True
                
            print(f"PUT flag bad status: {response.status_code}", file=sys.stderr)
            return False
            
        except requests.exceptions.RequestException as e:
            print(f"PUT flag error (attempt {attempt+1}): {str(e)}", file=sys.stderr)
            if attempt == MAX_RETRIES - 1:
                return False

def test_flag_get(session, flag_id, flag, vuln):
    """Тестирует получение флага."""
    for attempt in range(MAX_RETRIES):
        try:
            response = session.get(
                f"{BASE_URL}/api/flag/get",
                params={
                    "flag_id": flag_id,
                    "flag": flag,
                    "vuln": vuln
                },
                timeout=REQUEST_TIMEOUT
            )
            
            if response.status_code == 200:
                return True
                
            print(f"GET flag bad status: {response.status_code}", file=sys.stderr)
            return False
            
        except requests.exceptions.RequestException as e:
            print(f"GET flag error (attempt {attempt+1}): {str(e)}", file=sys.stderr)
            if attempt == MAX_RETRIES - 1:
                return False

def info():
    """Возвращает информацию о сервисе в формате A&D."""
    print("vulns: 1:1:1")
    return 101

def check(host):
    """Проверка доступности сервиса с замером времени выполнения этапов."""
    global BASE_URL
    BASE_URL = f"http://{host}:5000"

    try:
        print(f"[INFO] BASE_URL set to {BASE_URL}")
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=MAX_RETRIES)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        start = time.time()
        print("[INFO] Starting registration...")
        t0 = time.time()
        username, password = register(session)
        t1 = time.time()
        if not username:
            print("[ERROR] Registration failed", file=sys.stderr)
            return 1
        print(f"[SUCCESS] Registration complete in {t1 - t0:.3f}s")

        print("[INFO] Starting login...")
        t0 = time.time()
        if not login(session, username, password):
            print("[ERROR] Login failed", file=sys.stderr)
            return 1
        t1 = time.time()
        print(f"[SUCCESS] Login successful in {t1 - t0:.3f}s")

        test_message = "checker_test_" + str(time.time())
        print(f"[INFO] Sending chat message: {test_message}")
        t0 = time.time()
        if not send_chat_message(session, test_message, username):
            print("[ERROR] Chat test failed", file=sys.stderr)
            return 1
        t1 = time.time()
        print(f"[SUCCESS] Chat test passed in {t1 - t0:.3f}s")

        flag_id = "test_flag_" + str(time.time())
        flag = generate_flag("web")
        print(f"[INFO] Testing PUT with flag_id={flag_id}, flag={flag}")
        t0 = time.time()
        if not test_flag_put(session, flag_id, flag, 1):
            print("[ERROR] Flag PUT failed", file=sys.stderr)
            return 1
        t1 = time.time()
        print(f"[SUCCESS] Flag PUT passed in {t1 - t0:.3f}s")

        print(f"[INFO] Testing GET for flag_id={flag_id}")
        t0 = time.time()
        if not test_flag_get(session, flag_id, flag, 1):
            print("[ERROR] Flag GET failed", file=sys.stderr)
            return 1
        t1 = time.time()
        print(f"[SUCCESS] Flag GET passed in {t1 - t0:.3f}s")

        total = time.time() - start
        print(f"[INFO] Total check duration: {total:.3f}s")

        return 101

    except Exception as e:
        print(f"[EXCEPTION] Check error: {str(e)}", file=sys.stderr)
        return 1

def put(host, flag_id, flag, vuln):
    """Сохранение флага с замером времени."""
    global BASE_URL
    BASE_URL = f"http://{host}:5000"

    try:
        start = time.time()
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=MAX_RETRIES)
        session.mount('http://', adapter)

        t0 = time.time()
        if not login(session, "checker_user", "checker_pass"):
            print("Login failed in PUT", file=sys.stderr)
            return 1
        t1 = time.time()
        print(f"[INFO] Login in PUT completed in {t1 - t0:.3f}s")

        print("PUT operation started", file=sys.stdout)

        t0 = time.time()
        if not test_flag_put(session, flag_id, flag, vuln):
            print("Flag PUT failed", file=sys.stderr)
            return 1
        t1 = time.time()
        print(f"[INFO] PUT request completed in {t1 - t0:.3f}s")

        print(flag_id, file=sys.stderr)
        total = time.time() - start
        print(f"[INFO] Total PUT duration: {total:.3f}s")

        return 101

    except Exception as e:
        print(f"PUT error: {str(e)}", file=sys.stderr)
        return 1

def get(host, flag_id, flag, vuln):
    """Получение флага с замером времени."""
    global BASE_URL
    BASE_URL = f"http://{host}:5000"

    try:
        start = time.time()
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=MAX_RETRIES)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        t0 = time.time()
        if not login(session, "checker_user", "checker_pass"):
            print("Login failed in GET", file=sys.stderr)
            return 1
        t1 = time.time()
        print(f"[INFO] Login in GET completed in {t1 - t0:.3f}s")

        t0 = time.time()
        if not test_flag_get(session, flag_id, flag, vuln):
            print("Flag GET failed", file=sys.stderr)
            return 1
        t1 = time.time()
        print(f"[INFO] GET request completed in {t1 - t0:.3f}s")

        total = time.time() - start
        print(f"[INFO] Total GET duration: {total:.3f}s")

        return 101

    except Exception as e:
        print(f"GET error: {str(e)}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: checker.py <action> [args...]", file=sys.stderr)
        sys.exit(1)
    
    action = sys.argv[1]
    
    try:
        if action == "info":
            sys.exit(info())
            
        elif action == "check":
            host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
            sys.exit(check(host))
            
        elif action == "put":
            if len(sys.argv) < 6:
                print("Put requires host, flag_id, flag and vuln", file=sys.stderr)
                sys.exit(1)
            sys.exit(put(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])))
            
        elif action == "get":
            if len(sys.argv) < 6:
                print("Get requires host, flag_id, flag and vuln", file=sys.stderr)
                sys.exit(1)
            sys.exit(get(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])))
            
        else:
            print(f"Unknown action: {action}", file=sys.stderr)
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
