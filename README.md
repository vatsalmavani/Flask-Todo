# Flask-Todo

## Overview

This is a simple to-do list application built using Python's Flask framework. The application supports user registration, login, and personalized to-do lists. Users can add new items to their list and delete existing ones. Additionally, the application supports account deletion. It utilizes Flask-Login for user authentication, SQLite for data storage, Flask-WTF for form handling, and Flask-Bcrypt for password encryption.

## Features

* User registration and authentication
* Password hashing with Bcrypt
* Create, view, and delete todos
* Delete user account and associated todos
* Simple and clean user interface

## Installation

Clone the repository:
```bash
git clone https://github.com/vatsalmavani/Flask-Todo.git
cd Flask-Todo
```

Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

Install the dependencies:
```bash
pip install -r requirements.txt
```

Set up the database:
```bash
flask shell
>>> from app import db
>>> db.create_all()
>>> exit()
```

Run the application:
```bash
flask run
```

The application will be accessible at http://127.0.0.1:5000/.


## References

* https://flask.palletsprojects.com/en/3.0.x/
* https://flask-wtf.readthedocs.io/en/1.2.x/
* https://flask-login.readthedocs.io/en/latest/#flask_login.UserMixin
