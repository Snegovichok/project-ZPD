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

# Настройки
REQUEST_TIMEOUT = 5
SOCKETIO_TIMEOUT = 3
MAX_RETRIES = 3

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

def register(session, username, password):
    """Регистрирует пользователя."""
    for attempt in range(MAX_RETRIES):
        try:
            url = f"{BASE_URL}/register"
            response = session.get(url, timeout=REQUEST_TIMEOUT)
            token = get_csrf_token(response.text)
            
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
            
            return response.status_code == 200
        except requests.exceptions.RequestException:
            if attempt == MAX_RETRIES - 1:
                return False
            time.sleep(1)

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
            time.sleep(1)

def send_chat_message(session, message):
    """Отправляет сообщение в чат через SocketIO."""
    for attempt in range(MAX_RETRIES):
        try:
            sio = socketio.Client()
            cookies = session.cookies.get_dict()
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            
            sio.connect(
                BASE_URL,
                headers={'Cookie': cookie_str},
                wait_timeout=SOCKETIO_TIMEOUT
            )
            
            received = False
            
            @sio.on("message")
            def on_message(data):
                nonlocal received
                if data.get("message") == message:
                    received = True
            
            sio.emit("join", {"room": "general", "username": "checker_user"})
            sio.emit("send_message", {
                "room": "general",
                "username": "checker_user",
                "message": message
            })
            
            time.sleep(1)  # Даем время на обработку сообщения
            sio.disconnect()
            return received
            
        except Exception as e:
            print(f"SocketIO error (attempt {attempt+1}): {str(e)}", file=sys.stderr)
            if attempt == MAX_RETRIES - 1:
                return False
            time.sleep(1)

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
            time.sleep(1)

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
            time.sleep(1)

def info():
    """Возвращает информацию о сервисе в формате A&D."""
    print("vulns: 1:1:1")  # Укажите реальное количество уязвимостей
    return 101

def check(host):
    """Проверка доступности сервиса."""
    global BASE_URL
    BASE_URL = f"http://{host}:5000"
    
    try:
        # Создаем сессию с повторными попытками
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=MAX_RETRIES)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        # 1. Проверка регистрации
        if not register(session, "checker_user", "checker_pass"):
            print("Register failed after multiple attempts", file=sys.stderr)
            return 1
        
        # 2. Проверка авторизации
        if not login(session, "checker_user", "checker_pass"):
            print("Login failed after multiple attempts", file=sys.stderr)
            return 1
            
        # 3. Проверка работы чата
        test_message = "checker_test_" + str(time.time())
        if not send_chat_message(session, test_message):
            print("Chat message failed after multiple attempts", file=sys.stderr)
            return 1
            
        # 4. Проверка работы с флагами
        flag_id = "test_flag_" + str(time.time())
        flag = generate_flag("web")
        
        if not test_flag_put(session, flag_id, flag, 1):
            print("Flag PUT failed after multiple attempts", file=sys.stderr)
            return 1
            
        if not test_flag_get(session, flag_id, flag, 1):
            print("Flag GET failed after multiple attempts", file=sys.stderr)
            return 1
            
        return 101
        
    except Exception as e:
        print(f"Check error: {str(e)}", file=sys.stderr)
        return 1

def put(host, flag_id, flag, vuln):
    """Сохранение флага."""
    global BASE_URL
    BASE_URL = f"http://{host}:5000"
    
    try:
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=MAX_RETRIES)
        session.mount('http://', adapter)
        
        if not login(session, "checker_user", "checker_pass"):
            print("Login failed in PUT", file=sys.stderr)
            return 1
        
        # Добавляем вывод в stdout для совместимости
        print("PUT operation started", file=sys.stdout)
        
        if not test_flag_put(session, flag_id, flag, vuln):
            print("Flag PUT failed", file=sys.stderr)
            return 1
            
        print(flag_id, file=sys.stderr)
        return 101
        
    except Exception as e:
        print(f"PUT error: {str(e)}", file=sys.stderr)
        return 1

def get(host, flag_id, flag, vuln):
    """Получение флага."""
    global BASE_URL
    BASE_URL = f"http://{host}:5000"
    
    try:
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=MAX_RETRIES)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        if not login(session, "checker_user", "checker_pass"):
            print("Login failed in GET", file=sys.stderr)
            return 1
        
        if not test_flag_get(session, flag_id, flag, vuln):
            print("Flag GET failed", file=sys.stderr)
            return 1
            
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
