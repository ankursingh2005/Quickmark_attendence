from flask import Flask, render_template, request, redirect, url_for, flash, session 
import qrcode
import cv2
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime  
import hashlib
import os

app = Flask(__name__)
app.secret_key = 'MySuperSecretKey!@#2025_$%RandomChars'
DB_PATH = 'attendance.db'

# Database Initialization
if not os.path.exists(DB_PATH):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS students (
                        id INTEGER PRIMARY KEY, 
                        name TEXT, 
                        student_id TEXT UNIQUE,
                        email TEXT,
                        phone TEXT,
                        photo_path TEXT)
                   ''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS attendance (
                        student_id TEXT, 
                        date TEXT, 
                        status TEXT)
                   ''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE,
                        password_hash TEXT,
                        role TEXT,
                        email TEXT)
                   ''')
    conn.commit()
    conn.close()


def init_db():
    return sqlite3.connect(DB_PATH)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Generate QR code
@app.route('/generate_qr/<student_id>')
def generate_qr(student_id):
    conn = init_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM students WHERE student_id = ?", (student_id,))
    student = cursor.fetchone()
    conn.close()
    
    if student:
        name = student[0]
        qr_data = f"{student_id},{name}"
        qr = qrcode.make(qr_data)
        qr_path = f'static/qr_codes/{student_id}.png'
        os.makedirs(os.path.dirname(qr_path), exist_ok=True)
        qr.save(qr_path)
        flash(f'QR code generated for {name}!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Student not found.', 'danger')
        return redirect(url_for('dashboard'))

# Scan QR code
@app.route('/scan_qr', methods=['GET', 'POST'])
def scan_qr():
    if request.method == 'POST':
        qr_data = request.form.get('qr_data')
        if not qr_data:
            flash('No QR data received. Please try again.', 'danger')
            return redirect(url_for('scan_qr'))

        try:
            student_id, name = qr_data.split(',')
            date = datetime.now().strftime('%Y-%m-%d')
            
            conn = init_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO attendance (student_id, date, status) VALUES (?, ?, ?)", 
                           (student_id, date, 'Present'))
            conn.commit()
            conn.close()
            
            flash(f'Attendance marked for {name}!', 'success')
            return redirect(url_for('dashboard'))
        except ValueError:
            flash('Invalid QR data format.', 'danger')
            return redirect(url_for('scan_qr'))
    
    return render_template('scan_qr.html')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']
        
        conn = init_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
                           (username, hash_password(password), role, email))
            conn.commit()
            flash('User registered successfully!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Try another one.', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = init_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, role FROM users WHERE username = ? AND password_hash = ?",
                       (username, hash_password(password)))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['role'] = user[1]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Try again.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'role' in session:
        return render_template('dashboard.html', role=session['role'])
    else:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))

@app.route('/view_attendance')
def view_attendance():
    if 'role' in session:
        conn = init_db()
        cursor = conn.cursor()
        cursor.execute("SELECT student_id, date, status FROM attendance")
        records = cursor.fetchall()
        conn.close()
        return render_template('view_attendance.html', records=records)
    else:
        flash('Please log in to view attendance.', 'warning')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('home'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = init_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        
        if user:
            new_password = 'Temp1234'
            cursor.execute("UPDATE users SET password_hash = ? WHERE email = ?",
                           (hash_password(new_password), email))
            conn.commit()
            flash(f'Password reset successfully! Your new password is {new_password}', 'success')
        else:
            flash('Email not found. Try again.', 'danger')
        conn.close()
    return render_template('forgot_password.html')

if __name__ == '__main__':
    app.run(debug=True)
