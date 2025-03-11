#!/usr/bin/env python3
import sys
import json
import requests

def info(host):
    # Возвращает информацию о сервисе
    info = {
        "vulns": 1,
        "timeout": 10,
        "attack_data": False
    }
    print(json.dumps(info))

def check(host):
    # Проверка доступности сайта
    url = f"http://{host}:5000/"
    r = requests.get(url, timeout=5)
    if r.status_code != 200:
        sys.exit(1)
    sys.exit(0)

def put(host, flag_id, flag, vuln):
    # Сохраняем флаг через API
    url = f"http://{host}:5000/api/flag/put"
    data = {"flag_id": flag_id, "flag": flag, "vuln": vuln}
    r = requests.post(url, json=data, timeout=5)
    if r.status_code != 200:
        sys.exit(1)
    # Выводим флаг в stdout, а новый flag_id (в данном примере тот же) в stderr
    print(r.text)
    new_flag_id = r.headers.get("X-New-Flag-ID", "")
    if not new_flag_id:
        sys.exit(1)
    sys.stderr.write(new_flag_id)
    sys.exit(0)

def get(host, flag_id, flag, vuln):
    # Получаем флаг через API
    url = f"http://{host}:5000/api/flag/get"
    params = {"flag_id": flag_id, "flag": flag, "vuln": vuln}
    r = requests.get(url, params=params, timeout=5)
    if r.status_code != 200:
        sys.exit(1)
    sys.exit(0)

def main():
    if len(sys.argv) < 3:
        print("Usage: checker.py <action> <host> [args...]")
        sys.exit(1)
    action = sys.argv[1].lower()
    host = sys.argv[2]
    if action == "info":
        info(host)
    elif action == "check":
        check(host)
    elif action == "put":
        if len(sys.argv) != 6:
            print("Usage: checker.py put <host> <flag_id> <flag> <vuln>")
            sys.exit(1)
        put(host, sys.argv[3], sys.argv[4], sys.argv[5])
    elif action == "get":
        if len(sys.argv) != 6:
            print("Usage: checker.py get <host> <flag_id> <flag> <vuln>")
            sys.exit(1)
        get(host, sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        print("Unknown action")
        sys.exit(1)

if __name__ == "__main__":
    main()

