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
    if not user:
        return render_template('home.html')
    db = get_db()
    cur = db.execute('''SELECT 
                            questions.id as question_id, 
                            questions.question_text, 
                            askers.name as asker_name, 
                            experts.name as expert_name 
                            FROM questions 
                            JOIN users as askers ON askers.id = questions.asked_by_id 
                            join users as experts on experts.id = questions.expert_id
                            WHERE questions.answer_text is not null''')
    question_results = cur.fetchall()
    return render_template('home.html', user=user, question_results=question_results)

@app.route('/register', methods=['GET', 'POST'])
def register():
    user = get_current_user()
    db = get_db()
    error_message = None
    if request.method == 'POST':
        username = request.form['name'].lower()
        check_cur = db.execute('select id from users where name = ?',[username] )
        check_user_result = check_cur.fetchone()
        if check_user_result:
            error_message = "ERROR: User {} already exists!".format(username)
            return render_template('register.html', user=user, error=error_message)
        if request.form['password'] != request.form['retype_password']: # check password retype
            error_message = "ERROR: Passwords do not match!"
            return render_template('register.html', user=user, error=error_message)
        password = generate_password_hash(request.form['password'], method='sha256')
        db.execute('INSERT INTO users (name, password, expert, admin) VALUES (?, ?, ?, ?)', [username, password, False, False])
        db.commit()
        session['user'] = request.form['name'] # user session initialisation and login
        return redirect(url_for('index'))
    return render_template('register.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    user = get_current_user()
    db = get_db()
    error_message = None
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        check_cur = db.execute('select id from users where name = ?',[name] )
        check_user_result = check_cur.fetchone()
        if check_user_result:
            cur_user = db.execute('SELECT id, name, password FROM users WHERE name = ?', [name])
            user_results = cur_user.fetchone()
            hashed_password = user_results['password']
            if check_password_hash(hashed_password, password):
                session['user'] = user_results['name']
                return redirect(url_for('index'))
            else:
                error_message = "Error: Invalid password for user {}".format(name)
                return render_template('login.html', user=user, error=error_message)
        else:
            error_message = "Error: User {} does not exist".format(name)
            return render_template('login.html', user=user, error=error_message)
    return render_template('login.html', user=user)

@app.route('/question/<question_id>')
def question(question_id):
    user = get_current_user()
    db = get_db()
    cur = db.execute('SELECT questions.question_text, questions.answer_text, askers.name as asker_name, experts.name as expert_name FROM questions JOIN users as askers ON askers.id=questions.asked_by_id join users as experts on experts.id = questions.expert_id WHERE questions.id = ?', [question_id])
    question_result = cur.fetchone()
    return render_template('question.html', user=user, question_result=question_result)

@app.route('/answer/<question_id>', methods=['GET', 'POST'])
def answer(question_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    if user['expert'] == 0:
        return redirect(url_for('index'))
    db = get_db()
    if request.method == "POST":
        answer_text = request.form['answer']
        db.execute('update questions set answer_text = ? where id = ?', [answer_text, question_id])
        db.commit()
        return redirect(url_for('unanswered'))
    cur = db.execute('select id, question_text from questions where id = ?',[question_id])
    question = cur.fetchone()
    return render_template('answer.html', user=user, question=question)

@app.route('/ask', methods=['GET', 'POST'])
def ask():
    user = get_current_user()
    if not user:
        return redirect(url_for('login')) #  if user is not connected redirect it to login page
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

    if not user:
        return redirect(url_for('login'))
    if user['expert'] == 0:
        return redirect(url_for('index')) # if user is not expert then redirect it
    db = get_db()
    cur = db.execute('SELECT questions.id, questions.question_text, users.name FROM questions JOIN users ON users.id=questions.asked_by_id WHERE questions.answer_text is null AND expert_id = ?', [user['id']])
    questions_results = cur.fetchall()

    return render_template('unanswered.html', user=user, questions=questions_results)

@app.route('/users')
def users():
    user = get_current_user()
    if not user:
        return redirect(url_for('login')) # if user is not connected redirect it to login page
    if user['admin'] == 0:
        return redirect(url_for('index')) # if user is not administrator redirect it to home page
    db = get_db()
    cur = db.execute('SELECT id, name, admin, expert FROM users WHERE NOT admin = 1')
    users_results = cur.fetchall()
    return render_template('users.html', user=user, users_results=users_results)

@app.route('/promote/<promoted_user_id>')
def promote(promoted_user_id):
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    if user['admin'] == 0:
        return redirect(url_for('index')) # if user is not admin then redirect it
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
