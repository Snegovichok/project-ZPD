#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import os
import time
import socketio

# Адрес запущенного сервера
BASE_URL = "http://localhost:5000"

def get_csrf_token(html):
    """
    Извлекает CSRF-токен из HTML-страницы.
    """
    soup = BeautifulSoup(html, "html.parser")
    token_tag = soup.find("input", {"name": "csrf_token"})
    if token_tag:
        return token_tag.get("value")
    return None

def register(session, username, password):
    """
    Регистрирует пользователя через /register.
    """
    url = BASE_URL + "/register"
    # Получаем страницу регистрации для извлечения CSRF-токена
    response = session.get(url)
    token = get_csrf_token(response.text)
    data = {
        "username": username,
        "password": password,
        "csrf_token": token
    }
    response = session.post(url, data=data, allow_redirects=True)
    print("Регистрация:", response.url, response.status_code)
    return response

def login(session, username, password):
    """
    Входит в аккаунт через /login.
    """
    # Получаем главную страницу для CSRF-токена (если требуется)
    url = BASE_URL + "/"
    response = session.get(url)
    token = get_csrf_token(response.text)
    data = {
        "username": username,
        "password": password,
        "csrf_token": token
    }
    login_url = BASE_URL + "/login"
    response = session.post(login_url, data=data, allow_redirects=True)
    print("Вход:", response.url, response.status_code)
    return response

def send_chat_message(session, message):
    """
    Отправляет сообщение в общий чат через SocketIO.
    """
    # Создаём SocketIO-клиента и передаём cookies из сессии
    sio = socketio.Client()
    # Формируем заголовок Cookie из сессионных cookies
    cookies = session.cookies.get_dict()
    cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
    headers = {'Cookie': cookie_str}
    sio.connect(BASE_URL, headers=headers)
    
    # Присоединяемся к комнате "general"
    sio.emit("join", {"room": "general", "username": "123"})
    
    success = False  # Флаг успешности
    
    # Для отладки назначим обработчик полученных сообщений
    @sio.on("message")
    def on_message(data):
        print("Получено сообщение в чате:", data)
        if data.get("message") == message:
            nonlocal success
            success = True
    
    # Отправляем сообщение
    sio.emit("send_message", {"room": "general", "username": "123", "message": message})
    time.sleep(1)  # Ждём ответа от сервера
    sio.disconnect()
    
    return success  # Возвращаем True, если сообщение получено

def upload_file(session, file_path):
    """
    Загружает файл через /files.
    """
    url = BASE_URL + "/files"
    # Получаем страницу файлов для CSRF-токена
    response = session.get(url)
    token = get_csrf_token(response.text)
    # Подготавливаем файл для загрузки
    files = {"file": (os.path.basename(file_path), open(file_path, "rb"))}
    data = {"csrf_token": token}
    response = session.post(url, files=files, data=data, allow_redirects=True)
    print("Загрузка файла:", response.url, response.status_code)
    return response

def create_private_chat(session, password):
    """
    Если у пользователя уже существует приватный чат, возвращает его chat_id.
    Иначе создает новый чат и возвращает его chat_id.
    """
    url = BASE_URL + "/create_private_chat"
    
    # Сначала делаем GET-запрос для получения списка чатов
    response = session.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    
    # Предположим, что в таблице чатов ID чата находится в первом столбце каждой строки таблицы
    table = soup.find("table")
    if table:
        first_td = table.find("td")
        if first_td:
            chat_id = first_td.get_text(strip=True)
            if chat_id:
                print("Найден существующий чат с ID:", chat_id)
                return chat_id

    # Если чата нет, то создаём новый
    token = get_csrf_token(response.text)
    data = {"password": password, "csrf_token": token}
    response = session.post(url, data=data, allow_redirects=True)
    print("Создание приватного чата:", response.url, response.status_code)
    if "Приватный чат создан с ID:" in response.text:
        start = response.text.find("Приватный чат создан с ID:") + len("Приватный чат создан с ID:")
        # Используем регулярное выражение для извлечения числа, чтобы не терять символы
        import re
        match = re.search(r'(\d+)', response.text[start:])
        if match:
            chat_id = match.group(1)
            print("Создан приватный чат с ID:", chat_id)
            return chat_id
    return None

def join_private_chat(session, chat_id, password):
    """
    Подключается к приватному чату через /join_private_chat.
    """
    url = BASE_URL + "/join_private_chat"
    response = session.get(url)
    token = get_csrf_token(response.text)
    data = {"chat_id": chat_id, "password": password, "csrf_token": token}
    response = session.post(url, data=data, allow_redirects=True)
    print("Подключение к приватному чату:", response.url, response.status_code)
    return response
    
def send_private_chat_message(session, chat_id, message):
    """
    Отправляет сообщение в приватный чат через SocketIO, используя room=chat_id.
    """
    sio = socketio.Client()
    # Формируем заголовок Cookie из сессионных cookies
    cookies = session.cookies.get_dict()
    cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
    headers = {'Cookie': cookie_str}
    sio.connect(BASE_URL, headers=headers)
    
    # Присоединяемся к приватному чату с ID chat_id
    sio.emit("join", {"room": chat_id, "username": "123"})
    
    success = False  # Флаг успешности
    
    @sio.on("message")
    def on_message(data):
        print("Получено сообщение в приватном чате:", data)
        if data.get("message") == message:
            nonlocal success
            success = True
    
    # Отправляем сообщение в приватный чат
    sio.emit("send_message", {"room": chat_id, "username": "123", "message": message})
    time.sleep(1)  # Ждём ответа от сервера
    sio.disconnect()
    
    return success  # Возвращаем True, если сообщение получено

def logout(session):
    """
    Выходит из аккаунта через /logout.
    Для этого сначала получаем страницу (например, /account), где находится форма logout,
    извлекаем CSRF-токен и передаём его в POST-запросе.
    """
    logout_url = BASE_URL + "/logout"
    # Предположим, что форма для выхода находится на странице аккаунта
    account_url = BASE_URL + "/account"
    response = session.get(account_url)
    token = get_csrf_token(response.text)
    data = {"csrf_token": token}
    headers = {"Referer": account_url}
    response = session.post(logout_url, data=data, headers=headers, allow_redirects=True)
    print("Выход:", response.url, response.status_code)
    return response

def test_flag_put(session, flag_id, flag, vuln):
    """
    Тест сохранения флага через API.
    """
    url = BASE_URL + "/api/flag/put"
    data = {"flag_id": flag_id, "flag": flag, "vuln": vuln}
    
    response = session.post(url, json=data)
    print(f"Отправка флага {flag_id} -> Статус: {response.status_code}")
    
    if response.status_code == 200 and response.headers.get("X-New-Flag-ID") == flag_id:
        return True
    return False

def test_flag_get(session, flag_id, flag, vuln):
    """
    Тест получения флага через API.
    """
    url = BASE_URL + "/api/flag/get"
    params = {"flag_id": flag_id, "flag": flag, "vuln": vuln}

    response = session.get(url, params=params)
    print(f"Получение флага {flag_id} -> Статус: {response.status_code}")

    if response.status_code == 200 and response.text == "OK":
        return True
    return False
    
def test_flag_delete(session, flag_id, vuln):
    """
    Тест удаления флага через API.
    """
    url = BASE_URL + "/api/flag/delete"
    data = {"flag_id": flag_id, "vuln": vuln}

    response = session.delete(url, json=data)
    print(f"Удаление флага {flag_id} -> Статус: {response.status_code}")

    if response.status_code == 200 and response.text == "Deleted successfully":
        return True
    return False

def test_flag_update(session, flag_id, flag, vuln):
    """
    Тест обновления флага через API.
    """
    url = BASE_URL + "/api/flag/update"
    data = {"flag_id": flag_id, "flag": flag, "vuln": vuln}

    response = session.put(url, json=data)
    print(f"Обновление флага {flag_id} -> Статус: {response.status_code}")

    if response.status_code == 200 and response.text == "Updated successfully":
        return True
    return False

def test_flags_get_all(session, vuln):
    """
    Тест получения всех флагов по уязвимости через API.
    """
    url = BASE_URL + "/api/flags/get_all"
    params = {"vuln": vuln}

    response = session.get(url, params=params)
    print(f"Получение всех флагов для vuln={vuln} -> Статус: {response.status_code}")

    if response.status_code == 200 and len(response.json()) > 0:
        return True
    return False

def test_flags_get_by_id(session, flag_id):
    """
    Тест получения флагов по flag_id через API.
    """
    url = BASE_URL + "/api/flags/get_by_id"
    params = {"flag_id": flag_id}

    response = session.get(url, params=params)
    print(f"Получение флагов по ID {flag_id} -> Статус: {response.status_code}")

    if response.status_code == 200 and len(response.json()) > 0:
        return True
    return False

def main():
    session = requests.Session()
    failed_tests = []  # Список для хранения номеров невыполненных тестов

    # 1. Регистрация
    print("Тест 1: Регистрация")
    if not register(session, "123", "123"):
        failed_tests.append(1)

    # 2. Вход в аккаунт
    print("Тест 2: Вход")
    if not login(session, "123", "123"):
        failed_tests.append(2)

    # 3. Отправка сообщения в общий чат
    print("Тест 3: Отправка сообщения в общий чат")
    if not send_chat_message(session, "Тестовое сообщение"):
        failed_tests.append(3)

    # 4. Загрузка файла
    test_file = os.path.join("test", "test.txt")
    if not os.path.exists(test_file):
        print("Файл для теста не найден:", test_file)
        failed_tests.append(4)
    else:
        print("Тест 4: Загрузка файла")
        if not upload_file(session, test_file):
            failed_tests.append(4)

    # 5. Создание приватного чата
    print("Тест 5: Создание приватного чата")
    chat_id = create_private_chat(session, "123")
    if not chat_id:
        failed_tests.append(5)

    # 6. Подключение к приватному чату
    join_id = chat_id if chat_id is not None else "000001"
    print(f"Тест 6: Подключение к приватному чату с ID: {join_id}")
    if not join_private_chat(session, join_id, "123"):
        failed_tests.append(6)

    # 7. Отправка сообщения в приватный чат
    print(f"Тест 7: Отправка сообщения в приватном чате с ID: {join_id}")
    if not send_private_chat_message(session, join_id, "Тестовое сообщение"):
        failed_tests.append(7)

    # 8. Выход из аккаунта
    print("Тест 8: Выход из аккаунта")
    if not logout(session):
        failed_tests.append(8)

    # 9. API тест на сохранение флага
    print("Тест 9: Отправка флага")
    flag_id, flag, vuln = "flag123", "FLAG{test123}", 1
    if not test_flag_put(session, flag_id, flag, vuln):
        failed_tests.append(9)

    # 10. API тест на получение флага
    print("Тест 10: Получение флага")
    if not test_flag_get(session, flag_id, flag, vuln):
        failed_tests.append(10)

    # 11. API тест на обновление флага
    print("Тест 11: Обновление флага")
    updated_flag = "FLAG{updated123}"
    if not test_flag_update(session, flag_id, updated_flag, vuln):
        failed_tests.append(11)

    # 12. API тест на получение всех флагов по vuln
    print("Тест 12: Получение всех флагов по vuln")
    if not test_flags_get_all(session, vuln):
        failed_tests.append(12)

    # 13. API тест на получение флагов по flag_id
    print("Тест 13: Получение флагов по flag_id")
    if not test_flags_get_by_id(session, flag_id):
        failed_tests.append(13)
        
    # 14. API тест на удаление флага
    print("Тест 14: Удаление флага")
    if not test_flag_delete(session, flag_id, vuln):
        failed_tests.append(14)

    # Вывод результата
    if failed_tests:
        print("Не выполнены тесты:", ", ".join(map(str, failed_tests)))
    else:
        print("Все тесты выполнены успешно.")

if __name__ == '__main__':
    main()

