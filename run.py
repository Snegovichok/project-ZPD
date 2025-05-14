import subprocess

def main():
    subprocess.run(["docker-compose", "-f", "services/web/docker-compose.yml", "up", "--build"])

if __name__ == "__main__":
    main()

