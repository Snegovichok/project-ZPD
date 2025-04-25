# Secure Website vs. Vulnerable Website
These two websites were created for educational purposes. Works on any Windows/Linux/macOS platform. Very easy to install. This is a very good starting point for further development of this project.

## Views and html templates (the following pages are implemented):
- **base.html**: To simplify and avoid repetition in the code, we use the classic base tag in HTML.
- **index.html**: The main page, which is also the login. There are fields for logging into your account, and buttons for navigating to the "Registration" and "General Chat" pages.
- **chat.html**: The General Chat page, where you can view all messages and send messages, but only to registered users.
- **register.html**: The Registrations page, here you can create your first account to log in.
- **account.html**: The Account page opens here all the basic functionality of the web application, here you can click on the buttons to go to various pages: "General chat", "My files", "Create a private chat", "Connect to a private chat".
- **files.html**: The My Files page, here you can upload any file in any format to store your personal data on the server, the file size should not exceed 100 megabytes. All data remains with you in confidentiality, no one can download or receive it.
- **create_private_chat.html**: The Create Private Chat page, here you can create a private, secure chat that you can share with your friends for confidential correspondence.
- **join_private_chat.html**: The Connect to private chat page, here you need to enter the ID and password from the chat that a friend or yourself created.
- **private_chat.html**: The Private Chat page is where you can communicate privately with your friends or use it as a personal diary with notes.

## List of vulnerabilities:
1. SQL injection. It allows an attacker to manipulate database requests, which can lead to unauthorized access to confidential information.
2. Cross-Site Scripting (XSS). In this attack, malicious code is embedded in the page, which makes it possible to intercept user data or execute arbitrary scripts in the victim's browser.
3. CSRF (Cross-Site Request Forgery). Forces an authorized user to perform unwanted actions using their credentials.
4. XXE (XML External Entity). Exploiting an XML processing vulnerability can lead to the disclosure of internal files or the execution of remote requests.
5. Directory Traversal. The attacker gets access to files outside the web directory, which can lead to the leakage of confidential information.
6. IDOR (Insecure Direct Object Reference). Violating access control allows a user to view other users' data.
7. Insecure Deserialization. Allows an attacker to inject and execute arbitrary code through data deserialization.
8. Open Redirect and SSRF (Server-Side Request Forgery). An open redirect can redirect a user to a malicious site, and SSRF can force the server to make requests to internal resources.

# DESCRIPTION
**Project ZPD version 1.0:**
At first, I created the most secure web application as possible according to my knowledge in Python Flask development.
Then, using the same code, without any changes to the HTML/CSS/JS templates, I modified it to contain several vulnerabilities that I described above. In the codes "secure_app.py" and "vulnerable_app.py" themselves, you can visually see where the vulnerabilities may be if you write the code very poorly.

# SETUP AND INSTALLATION INSTRUCTIONS
## How to set up or launch a project:
1. Install Python software from the official website on your OS (Linux/Windows/macOS) "https://www.python.org".
2. Download the project-ZPD folder and place it in any convenient location.
3. Open the "..\project-ZPD\services\web\" directory. And the command line (terminal) itself with this location, which has Python.
4. Install all necessary pip dependencies from the file requirements.txt:
- pip install -r requirements.txt
5. Now you can run the web application while staying in the same directory in the terminal:
- "python secure_app.py" or "python vulnerable_app.py"
- Note: Run only one. To stop the server, use Ctrl + C in the terminal.
## Result
You should have a link to the server (at http://0.0.0.0:5000 or http://localhost:5000). Open it in any browser.
## Addition:
- You can also run "check.py" for checking the health of web applications.
1. Open the folder with the "..\project-ZPD\" directory in the new terminal.
2. Install all necessary pip dependencies from the file requirements.txt:
- pip install -r requirements.txt
3. Now you can check web applications while staying in the same terminal directory:
- python check.py
- Note: Before launching, make sure that one of the web applications is running.
4. To clean the database, use the following command:
- python clear.py
- Note: Or manually delete the "instance" and "uploads" folders in the "..\project-ZPD\services\web\" directory.

# IF YOU ARE GOING TO USE DOCKER:
## My stack of used technologies:
- Windows 10
- VirtualBox 7.0.12
- Ubuntu 22.04.3 LTS
- Python 3.10.12
- Flask
- Docker Engine
- SQLite and SQLAlchemy database
- Basic HTML/CSS/JS for minimal page design

## To install my technology pool:
1. Install VirtualBox software from the official website on your OS (Linux/Windows/macOS) "https://www.virtualbox.org/".
2. Download Ubuntu 22.04.3 LTS from the official website to your operating system "https://ubuntu.com/".
3. Install the Ubuntu image in VirtualBox.
4. Install Python software in Ubuntu using the official website information "https://www.python.org ".
5. Install Docker Engine on Ubuntu using the official website information "https://docs.docker.com/engine/install/ubuntu/".

## How to set up or launch a project:
1. Download and open project-ZPD folder.
2. Open the "../project-ZPD" directory. And the command line (terminal) itself with this location, which has Python.
3. Now you can enter the following commands in terminal:
- **To start the Docker server, simply enter the following command:**
- sudo python3 run.py
- Note: To launch secure_app.py edit the "Dockerfile" file in the folder with the "../project-ZPD/services/web" directory. To stop the server, use Ctrl + C in the terminal.
- **To clean the Docker server, simply type the following command:**
- sudo python3 restart.py
- **To use the tests, install additional libraries for Python. To do this, run the following command:**
- python setup.py
- **To test the functionality of the web application, simply enter the following command:**
- python check.py
- **To clean the database, use the following command:**
- python clear.py
- Note: In case of failure to delete folders "sudo python clear.py".
