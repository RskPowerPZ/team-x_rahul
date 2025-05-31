import os
import sys
import subprocess
import threading
import sqlite3
import traceback
import signal
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'AKIRU_@2025!Te@m-S3cr3t-K3y#7h1s!$V3ry$tr0ng')
app.config['UPLOAD_FOLDER'] = '/var/data/user_bots'  # Persistent storage path for Render
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload folder exists
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)

# Process management
running_processes = {}
process_logs = {}

# Database setup
def init_db():
    with sqlite3.connect('bot_data.db') as conn:
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
                    FOREIGN KEY(file_id) REFERENCES files(id))''')
        conn.commit()

init_db()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'py', 'js', 'zip'}

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect('bot_data.db') as conn:
        c = conn.cursor()
        c.execute('SELECT id, filename, filetype FROM files WHERE user_id = ?', (session['user_id'],))
        files = c.fetchall()
    
    file_status = []
    for file in files:
        file_id, filename, filetype = file
        is_running = file_id in running_processes and running_processes[file_id].poll() is None
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with sqlite3.connect('bot_data.db') as conn:
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE username = ? AND password = ?', (username, password))
            user = c.fetchone()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with sqlite3.connect('bot_data.db') as conn:
            c = conn.cursor()
            try:
                c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
                conn.commit()
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists', 'error')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect('bot_data.db') as conn:
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM files WHERE user_id = ?', (session['user_id'],))
        file_count = c.fetchone()[0]
        
        if file_count >= 5:
            flash('You can only upload up to 5 files', 'error')
            return redirect(url_for('index'))
        
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('index'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('index'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filetype = filename.rsplit('.', 1)[1].lower()
            
            user_folder = Path(app.config['UPLOAD_FOLDER']) / str(session['user_id'])
            user_folder.mkdir(exist_ok=True)
            
            filepath = user_folder / filename
            file.save(filepath)
            
            c.execute('INSERT INTO files (user_id, filename, filetype, upload_date) VALUES (?, ?, ?, ?)',
                      (session['user_id'], filename, filetype, datetime.now().isoformat()))
            conn.commit()
            
            flash('File uploaded successfully', 'success')
            return redirect(url_for('index'))
        
        flash('Invalid file type. Only .py, .js, and .zip files are allowed', 'error')
        return redirect(url_for('index'))

def handle_signal(signum, frame):
    """Graceful shutdown handler"""
    for pid in running_processes.values():
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_signal)

@app.route('/control/<int:file_id>/<action>')
def control_file(file_id, action):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect('bot_data.db') as conn:
        c = conn.cursor()
        c.execute('SELECT filename, filetype FROM files WHERE id = ? AND user_id = ?', 
                 (file_id, session['user_id']))
        file = c.fetchone()
        
        if not file:
            flash('File not found', 'error')
            return redirect(url_for('index'))
        
        filename, filetype = file
        user_folder = Path(app.config['UPLOAD_FOLDER']) / str(session['user_id'])
        filepath = user_folder / filename
        
        if action == 'start':
            try:
                # Create logs directory
                logs_dir = Path('/var/data/logs')
                logs_dir.mkdir(exist_ok=True)
                
                log_file = logs_dir / f'{file_id}.log'
                
                if filetype == 'py':
                    process = subprocess.Popen(
                        [sys.executable, str(filepath)],
                        stdout=open(log_file, 'a'),
                        stderr=subprocess.STDOUT,
                        stdin=subprocess.PIPE,
                        shell=False,
                        preexec_fn=os.setsid
                    )
                elif filetype == 'js':
                    process = subprocess.Popen(
                        ['node', str(filepath)],
                        stdout=open(log_file, 'a'),
                        stderr=subprocess.STDOUT,
                        stdin=subprocess.PIPE,
                        shell=False,
                        preexec_fn=os.setsid
                    )
                else:
                    flash('Unsupported file type', 'error')
                    return redirect(url_for('index'))
                
                running_processes[file_id] = process
                
                # Write PID to file
                with open(logs_dir / f'{file_id}.pid', 'w') as f:
                    f.write(str(process.pid))
                
                # Start log monitoring
                threading.Thread(
                    target=monitor_process,
                    args=(file_id, process, str(log_file)),
                    daemon=True
                ).start()
                
                flash('Script started successfully', 'success')
                return redirect(url_for('index'))
            
            except Exception as e:
                flash(f'Error starting script: {str(e)}', 'error')
                app.logger.error(f"Start error: {traceback.format_exc()}")
                return redirect(url_for('index'))
        
        elif action == 'stop':
            if file_id not in running_processes:
                flash('Script is not running', 'error')
                return redirect(url_for('index'))
            
            process = running_processes[file_id]
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            
            del running_processes[file_id]
            
            # Clean up PID file
            pid_file = Path('/var/data/logs') / f'{file_id}.pid'
            if pid_file.exists():
                pid_file.unlink()
            
            flash('Script stopped successfully', 'success')
            return redirect(url_for('index'))
        
        flash('Invalid action', 'error')
        return redirect(url_for('index'))

def monitor_process(file_id, process, log_path):
    """Monitor process and collect logs"""
    with open(log_path, 'r') as f:
        while True:
            output = f.readline()
            if not output and process.poll() is not None:
                break
            if output:
                process_logs.setdefault(file_id, []).append(output.strip())

@app.route('/logs/<int:file_id>')
def get_logs(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect('bot_data.db') as conn:
        c = conn.cursor()
        c.execute('SELECT 1 FROM files WHERE id = ? AND user_id = ?', 
                 (file_id, session['user_id']))
        if not c.fetchone():
            flash('Access denied', 'error')
            return redirect(url_for('index'))
    
    if file_id not in process_logs:
        return jsonify([])
    
    return jsonify(process_logs[file_id][-100:])  # Return last 100 lines

@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect('bot_data.db') as conn:
        c = conn.cursor()
        c.execute('SELECT filename FROM files WHERE id = ? AND user_id = ?', 
                 (file_id, session['user_id']))
        file = c.fetchone()
        
        if not file:
            flash('File not found', 'error')
            return redirect(url_for('index'))
        
        filename = file[0]
        
        # Stop if running
        if file_id in running_processes:
            try:
                os.killpg(os.getpgid(running_processes[file_id].pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            del running_processes[file_id]
        
        # Delete from filesystem
        user_folder = Path(app.config['UPLOAD_FOLDER']) / str(session['user_id'])
        filepath = user_folder / filename
        if filepath.exists():
            filepath.unlink()
        
        # Delete from database
        c.execute('DELETE FROM files WHERE id = ?', (file_id,))
        c.execute('DELETE FROM processes WHERE file_id = ?', (file_id,))
        conn.commit()
        
        flash('File deleted successfully', 'success')
        return redirect(url_for('index'))

if __name__ == '__main__':
    # Create required directories
    Path(app.config['UPLOAD_FOLDER']).mkdir(exist_ok=True)
    Path('/var/data/logs').mkdir(exist_ok=True)
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
