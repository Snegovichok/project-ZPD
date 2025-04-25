import os
import subprocess

def main():
    subprocess.run(["rm", "-r", "instance"], cwd="services/web")
    subprocess.run(["rm", "-r", "uploads"], cwd="services/web")

if __name__ == "__main__":
    main()

