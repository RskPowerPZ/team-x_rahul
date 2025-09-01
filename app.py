import os
import subprocess
import threading
import sqlite3
import traceback
import signal
import time
import collections
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)

# Configuration - Optimized for Render and local
app.secret_key = 'AKIRU_' + os.urandom(32).hex() + '@2025'  # Auto-generated secret key
app.config['UPLOAD_FOLDER'] = '/var/data/user_bots' if 'RENDER' in os.environ else 'user_bots'
app.config['DATABASE_PATH'] = '/var/data/bot_data.db' if 'RENDER' in os.environ else 'bot_data.db'
app.config['LOG_DIR'] = '/var/data/logs' if 'RENDER' in os.environ else 'logs'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['MAX_CONCURRENT_PER_USER'] = 5  # Optional: Limit concurrent processes per user
app.config['LOG_LINES_IN_MEMORY'] = 100  # Keep last N log lines in memory

# Ensure directories exist
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)
Path(app.config['LOG_DIR']).mkdir(parents=True, exist_ok=True)

# Thread safety
lock = threading.Lock()  # Added lock for thread-safe access to shared dicts

# Process management - Use pid instead of Popen for easier recovery
running_processes = {}  # file_id -> pid
process_logs = {}  # file_id -> deque of last N log lines

# Database setup with persistent storage
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE_PATH'])
    conn.execute('PRAGMA foreign_keys = ON')  # Enforce foreign keys
    return conn

def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE,
                     password TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS files
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     user_id INTEGER,
                     filename TEXT,
                     filetype TEXT,
                     upload_date TEXT,
                     FOREIGN KEY(user_id) REFERENCES users(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS processes
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     file_id INTEGER,
                     pid INTEGER,
                     start_time TEXT,
                     log_path TEXT,
                     FOREIGN KEY(file_id) REFERENCES files(id))''')
        conn.commit()

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'py', 'js', 'zip'}

def load_running_processes():
    """Load and verify running processes from DB on app startup"""
    dels = []
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT file_id, pid, log_path FROM processes')
        rows = c.fetchall()
    for file_id, pid, log_path in rows:
        try:
            os.kill(pid, 0)  # Check if process is alive
        except OSError:
            dels.append(file_id)
            continue
        with lock:
            running_processes[file_id] = pid
            process_logs[file_id] = collections.deque(maxlen=app.config['LOG_LINES_IN_MEMORY'])
            if os.path.exists(log_path):
                with open(log_path, 'r') as lf:
                    lines = [l.strip() for l in lf.readlines()[-app.config['LOG_LINES_IN_MEMORY']:]]
                    process_logs[file_id].extend(lines)
        # Start monitoring thread to tail logs and detect end
        threading.Thread(target=monitor_process, args=(file_id, pid, log_path), daemon=True).start()
    # Clean up dead processes from DB after checking
    if dels:
        with get_db_connection() as conn:
            c = conn.cursor()
            for file_id in dels:
                c.execute('DELETE FROM processes WHERE file_id = ?', (file_id,))
            conn.commit()

def monitor_process(file_id, pid, log_path):
    """Monitor log file for new lines and check if process ends"""
    try:
        with open(log_path, 'r') as f:
            f.seek(0, 2)  # Seek to end of file
            while True:
                line = f.readline()
                if line:
                    with lock:
                        if file_id in process_logs:
                            process_logs[file_id].append(line.strip())
                else:
                    # No new line, check if process is still alive
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        break
                    time.sleep(0.1)  # Avoid busy loop
    except Exception as e:
        traceback.print_exc()
    finally:
        # Clean up when process ends or error
        with lock:
            if file_id in running_processes:
                del running_processes[file_id]
            if file_id in process_logs:
                del process_logs[file_id]
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM processes WHERE file_id = ?', (file_id,))
            conn.commit()

def start_process(file_id, filepath, filetype):
    """Start a process with proper logging and background execution"""
    log_path = os.path.join(app.config['LOG_DIR'], f'process_{file_id}.log')
    try:
        # Clear previous log if starting new
        if os.path.exists(log_path):
            os.remove(log_path)
        open(log_path, 'w').close()

        if filetype == 'py':
            cmd = ['python', filepath]
        elif filetype == 'js':
            cmd = ['node', filepath]
        elif filetype == 'zip':
            # TODO: Handle zip - e.g., extract and run entry point (not implemented for simplicity)
            return False
        else:
            return False

        # Start subprocess in background with process group
        process = subprocess.Popen(
            cmd,
            stdout=open(log_path, 'a'),
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid  # Detached process group for 24x7 running
        )
        pid = process.pid

        with lock:
            running_processes[file_id] = pid
            process_logs[file_id] = collections.deque(maxlen=app.config['LOG_LINES_IN_MEMORY'])

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO processes (file_id, pid, start_time, log_path) VALUES (?, ?, ?, ?)',
                      (file_id, pid, datetime.now().isoformat(), log_path))
            conn.commit()

        # Start log monitoring thread
        threading.Thread(
            target=monitor_process,
            args=(file_id, pid, log_path),
            daemon=True
        ).start()

        return True
    except Exception as e:
        traceback.print_exc()
        return False

def stop_process(file_id):
    """Stop a running process safely"""
    with lock:
        if file_id in running_processes:
            pid = running_processes[file_id]
            try:
                os.killpg(pid, signal.SIGTERM)  # Terminate process group
            except OSError:
                pass
            del running_processes[file_id]
            if file_id in process_logs:
                del process_logs[file_id]
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('DELETE FROM processes WHERE file_id = ?', (file_id,))
        conn.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Missing credentials', 'error')
            return render_template('login.html')
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            if user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                session['username'] = username
                flash('Logged in successfully', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Missing credentials', 'error')
            return render_template('register.html')
        hashed_password = generate_password_hash(password)
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                conn.commit()
                flash('Registered successfully', 'success')
                return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'success')
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('index'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Prevent path traversal
        ext = filename.rsplit('.', 1)[1].lower()
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']))
        os.makedirs(user_dir, exist_ok=True)  # User-specific folder
        filepath = os.path.join(user_dir, filename)
        file.save(filepath)
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO files (user_id, filename, filetype, upload_date) VALUES (?, ?, ?, ?)',
                      (session['user_id'], filename, ext, datetime.now().isoformat()))
            conn.commit()
        flash('File uploaded successfully', 'success')
    else:
        flash('Invalid file type', 'error')
    return redirect(url_for('index'))

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT id, filename, filetype FROM files WHERE user_id = ?', (session['user_id'],))
        files = c.fetchall()
    file_status = []
    with lock:
        for file in files:
            file_id, filename, filetype = file
            is_running = file_id in running_processes
            if is_running:
                try:
                    os.kill(running_processes[file_id], 0)
                except OSError:
                    is_running = False
                    stop_process(file_id)  # Clean up if dead
            file_status.append({
                'id': file_id,
                'name': filename,
                'type': filetype,
                'running': is_running
            })
    return render_template('index.html',
                           files=file_status,
                           username=session.get('username'),
                           server_type="Render" if 'RENDER' in os.environ else "Local")

@app.route('/control/<int:file_id>/<action>')
def control_file(file_id, action):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT filename, filetype FROM files WHERE id = ? AND user_id = ?',
                  (file_id, session['user_id']))
        file = c.fetchone()
        if not file:
            flash('File not found or access denied', 'error')
            return redirect(url_for('index'))
        # Check concurrent limit
        if action == 'start':
            c.execute('''SELECT COUNT(*) FROM processes p
                         JOIN files f ON p.file_id = f.id
                         WHERE f.user_id = ?''', (session['user_id'],))
            count = c.fetchone()[0]
            if count >= app.config['MAX_CONCURRENT_PER_USER']:
                flash(f'Max {app.config["MAX_CONCURRENT_PER_USER"]} concurrent processes allowed', 'error')
                return redirect(url_for('index'))
        filename, filetype = file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']), filename)
        if action == 'start':
            with lock:
                if file_id in running_processes:
                    flash('This file is already running', 'error')
                    return redirect(url_for('index'))
            started = start_process(file_id, filepath, filetype)
            if started:
                flash('Script started successfully', 'success')
            else:
                flash('Error starting script (unsupported type or failure)', 'error')
            return redirect(url_for('index'))
        elif action == 'stop':
            stop_process(file_id)
            flash('Script stopped successfully', 'success')
            return redirect(url_for('index'))
    flash('Invalid action', 'error')
    return redirect(url_for('index'))

@app.route('/logs/<int:file_id>')
def get_logs(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Verify ownership
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT 1 FROM files WHERE id = ? AND user_id = ?',
                  (file_id, session['user_id']))
        if not c.fetchone():
            flash('Access denied', 'error')
            return redirect(url_for('index'))
    # Get logs from memory if available
    with lock:
        logs = list(process_logs.get(file_id, []))
    # Fallback to disk if not in memory (e.g., after stop or restart)
    if not logs:
        log_path = os.path.join(app.config['LOG_DIR'], f'process_{file_id}.log')
        if os.path.exists(log_path):
            try:
                with open(log_path, 'r') as f:
                    logs = [l.strip() for l in f.readlines()[-app.config['LOG_LINES_IN_MEMORY']:]]
            except IOError:
                pass
    return jsonify(logs)

if __name__ == '__main__':
    load_running_processes()  # Recover running processes on startup
    if 'RENDER' in os.environ:
        app.config['UPLOAD_FOLDER'] = '/var/data/user_bots'
        app.config['DATABASE_PATH'] = '/var/data/bot_data.db'
        app.config['LOG_DIR'] = '/var/data/logs'
        Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)
        Path(app.config['LOG_DIR']).mkdir(parents=True, exist_ok=True)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, threaded=True)  # Threaded for concurrency
