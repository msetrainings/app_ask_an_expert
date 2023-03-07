from flask import Flask, render_template, g, request, redirect, url_for, jsonify, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os


app = Flask(__name__)
app.config['DEBUG'] = True
app.secret_key = os.urandom(24)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "questions.db")

class IncorretPasswordError(Exception):
    def __init__(self, message="Incorrect password!"):
        self.message = message
        super().__init__(self.message)

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

def get_current_user():
    """
    Get user session informations
    """
    user_result = None
    if 'user' in session:
        user = session['user']
        db = get_db()
        cur_user = db.execute('SELECT id, name, password, expert, admin FROM users WHERE name = ?', [user])
        user_result = cur_user.fetchone()
    return user_result

@app.route('/')
def index():
    user = get_current_user()
    return render_template('home.html', user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    user = get_current_user()
    db = get_db()
    if request.method == 'POST':
        try:
            username = request.form['name'].lower()
            password = generate_password_hash(request.form['password'], method='sha256')
            db.execute('INSERT INTO users (name, password, expert, admin) VALUES (?, ?, ?, ?)', [username, password, False, False])
            db.commit()
            session['user'] = request.form['name'] # user session initialisation and login
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            return f"Oops :( User {username} is already used. Please choose another username"
    return render_template('register.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    user = get_current_user()
    db = get_db()
    if request.method == 'POST':
        try:    
            name = request.form['name']
            password = request.form['password']
            cur_user = db.execute('SELECT id, name, password FROM users WHERE name = ?', [name])
            user_results = cur_user.fetchone()
            hashed_password = user_results['password']
            if check_password_hash(hashed_password, password):
                session['user'] = user_results['name']
                return redirect(url_for('index'))
            else:
                error_message = 'Error: Invalid Password!'
                return f"{error_message}"
        except TypeError:
            return f"user {request.form['name']} don't exist!"
    return render_template('login.html', user=user)

@app.route('/question')
def question():
    user = get_current_user()
    return render_template('question.html', user=user)

@app.route('/answer')
def answer():
    user = get_current_user()
    return render_template('answer.html', user=user)

@app.route('/ask', methods=['GET', 'POST'])
def ask():
    user = get_current_user()
    db = get_db()
    if request.method == "POST":
        question = request.form['question']
        asker = user['id']
        expert = request.form['expert']
        db.execute('insert into questions (question_text, asked_by_id, expert_id) values (?, ?, ?)', [question, asker, expert])
        db.commit()
        return redirect(url_for('index'))
    
    cur = db.execute('SELECT id, name FROM users WHERE expert = 1')
    experts = cur.fetchall()
    return render_template('ask.html', user=user, experts=experts)

@app.route('/unanswered')
def unanswered():
    user = get_current_user()
    db = get_db()
    cur = db.execute('''SELECT questions.id, questions.question_text, users.name
                        FROM questions
                        JOIN users ON users.id=questions.asked_by_id''')
    questions_results = cur.fetchall()

    return render_template('unanswered.html', user=user, questions=questions_results)

@app.route('/users')
def users():
    user = get_current_user()
    if 'user' in session:
        db = get_db()
        cur = db.execute('SELECT id, name, admin, expert FROM users WHERE NOT admin = 1')
        users_results = cur.fetchall()
        return render_template('users.html', user=user, users_results=users_results)
    else:
        return "not connected"

@app.route('/promote/<promoted_user_id>')
def promote(promoted_user_id):
    db = get_db()
    db.execute('UPDATE users set expert = 1 where id = ?', [promoted_user_id])
    db.commit()
    return redirect(url_for('users'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
