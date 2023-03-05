from flask import Flask, render_template, g, request, redirect, url_for, jsonify, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['DEBUG'] = True
app.secret_key = os.urandom(24)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "questions.db")

def connect_db():
    sql = sqlite3.connect(db_path)
    sql.row_factory = sqlite3.Row # return dictionary instead of tuple
    return sql

def get_db():
    if not hasattr(g, 'sqlite3'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


@app.route('/')
def index():
    user = None
    if 'user' in session:
        user = session['user']
    return render_template('home.html', user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    db = get_db()
    if request.method == 'POST':
        username = request.form['name']
        password = generate_password_hash(request.form['password'], method='sha256')
        db.execute('INSERT INTO users (name, password, expert, admin) VALUES (?, ?, ?, ?)', [username, password, False, False])
        db.commit()
        return f"User {username} successfully created"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        cur_user = db.execute('SELECT id, name, password FROM users WHERE name = ?', [name])
        user_results = cur_user.fetchone()
        hashed_password = user_results['password']
        if check_password_hash(hashed_password, password):
            session['user'] = user_results['name']
            return "The password is correct"
        else:
            return "The password is incorrect"
    return render_template('login.html')

@app.route('/question')
def question():
    return render_template('question.html')

@app.route('/answer')
def answer():
    return render_template('answer.html')

@app.route('/ask')
def ask():
    return render_template('ask.html')

@app.route('/unanswered')
def unanswered():
    return render_template('unanswered.html')

@app.route('/users')
def users():
    return render_template('users.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
