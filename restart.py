import os
import subprocess

def main():
    subprocess.run(["docker-compose", "down"], cwd="services/web/")
    subprocess.run(["docker", "system", "prune", "-a", "-f"], cwd="services/web/")

if __name__ == "__main__":
    main()

