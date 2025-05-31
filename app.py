import os
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

# Configuration - Optimized for Render
app.secret_key = 'AKIRU_'+os.urandom(32).hex()+'@2025'  # Auto-generated secret key
app.config['UPLOAD_FOLDER'] = '/var/data/user_bots' if 'RENDER' in os.environ else 'user_bots'
app.config['DATABASE_PATH'] = '/var/data/bot_data.db' if 'RENDER' in os.environ else 'bot_data.db'
app.config['LOG_DIR'] = '/var/data/logs' if 'RENDER' in os.environ else 'logs'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure directories exist
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)
Path(app.config['LOG_DIR']).mkdir(parents=True, exist_ok=True)

# Process management
running_processes = {}
process_logs = {}

# Database setup with persistent storage
def get_db_connection():
    return sqlite3.connect(app.config['DATABASE_PATH'])

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

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT id, filename, filetype FROM files WHERE user_id = ?', (session['user_id'],))
        files = c.fetchall()
    
    file_status = []
    for file in files:
        file_id, filename, filetype = file
        is_running = False
        
        # Check both memory and database for running status
        if file_id in running_processes:
            is_running = running_processes[file_id].poll() is None
        else:
            # Check database for previously running processes
            c.execute('SELECT pid FROM processes WHERE file_id = ?', (file_id,))
            pid_record = c.fetchone()
            if pid_record:
                try:
                    # Check if process is still running
                    os.kill(pid_record[0], 0)
                    is_running = True
                except (OSError, ProcessLookupError):
                    pass
        
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

# [Rest of your routes remain unchanged, but use get_db_connection() instead of sqlite3.connect()]

def start_process(file_id, filepath, filetype):
    """Start a process with proper logging"""
    log_path = os.path.join(app.config['LOG_DIR'], f'process_{file_id}.log')
    
    # Clear previous log file
    if os.path.exists(log_path):
        os.remove(log_path)
    
    # Create new log file
    open(log_path, 'w').close()
    
    try:
        if filetype == 'py':
            process = subprocess.Popen(
                ['python', filepath],
                stdout=open(log_path, 'w'),
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=os.setsid  # For proper process group handling
            )
        elif filetype == 'js':
            process = subprocess.Popen(
                ['node', filepath],
                stdout=open(log_path, 'w'),
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=os.setsid
            )
        else:
            return None
        
        running_processes[file_id] = process
        
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('INSERT INTO processes (file_id, pid, start_time, log_path) VALUES (?, ?, ?, ?)',
                     (file_id, process.pid, datetime.now().isoformat(), log_path))
            conn.commit()
        
        # Start log monitoring thread
        threading.Thread(
            target=monitor_process,
            args=(file_id, process, log_path),
            daemon=True
        ).start()
        
        return process
    except Exception as e:
        print(f"Error starting process: {str(e)}")
        return None

def monitor_process(file_id, process, log_path):
    """Monitor process and collect logs"""
    try:
        with open(log_path, 'r') as f:
            while True:
                output = f.readline()
                if not output and process.poll() is not None:
                    break
                if output:
                    process_logs.setdefault(file_id, []).append(output.strip())
    finally:
        # Clean up when process ends
        if file_id in running_processes:
            del running_processes[file_id]
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM processes WHERE file_id = ?', (file_id,))
            conn.commit()

def stop_process(file_id):
    """Stop a running process"""
    if file_id in running_processes:
        try:
            # Kill the entire process group
            os.killpg(os.getpgid(running_processes[file_id].pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        del running_processes[file_id]
    
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('DELETE FROM processes WHERE file_id = ?', (file_id,))
        conn.commit()
    
    # Clear logs
    if file_id in process_logs:
        del process_logs[file_id]

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
            flash('File not found', 'error')
            return redirect(url_for('index'))
        
        filename, filetype = file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']), filename)
        
        if action == 'start':
            if file_id in running_processes:
                flash('This file is already running', 'error')
                return redirect(url_for('index'))
            
            process = start_process(file_id, filepath, filetype)
            if process:
                flash('Script started successfully', 'success')
            else:
                flash('Error starting script', 'error')
            
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
    
    # Verify user owns this file
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT 1 FROM files WHERE id = ? AND user_id = ?', 
                  (file_id, session['user_id']))
        if not c.fetchone():
            flash('Access denied', 'error')
            return redirect(url_for('index'))
    
    # Try to get logs from memory
    logs = process_logs.get(file_id, [])
    
    # If no logs in memory, try to read from log file
    if not logs:
        c.execute('SELECT log_path FROM processes WHERE file_id = ?', (file_id,))
        log_path_record = c.fetchone()
        if log_path_record and os.path.exists(log_path_record[0]):
            try:
                with open(log_path_record[0], 'r') as f:
                    logs = f.readlines()[-100:]  # Get last 100 lines
            except IOError:
                pass
    
    return jsonify(logs)

if __name__ == '__main__':
    # Initialize Render persistent storage paths
    if 'RENDER' in os.environ:
        # These paths will persist across deploys
        app.config['UPLOAD_FOLDER'] = '/var/data/user_bots'
        app.config['DATABASE_PATH'] = '/var/data/bot_data.db'
        app.config['LOG_DIR'] = '/var/data/logs'
        
        # Ensure directories exist
        Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)
        Path(app.config['LOG_DIR']).mkdir(parents=True, exist_ok=True)
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
