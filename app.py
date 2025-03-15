from flask import Flask, render_template, request, redirect, url_for, flash, session, get_flashed_messages  
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
@app.context_processor
def inject_messages():
    return dict(messages=get_flashed_messages(with_categories=True))

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

# View attendance
@app.route('/view_attendance')
def view_attendance():
    conn = init_db()
    cursor = conn.cursor()
    
    if session.get('role') == 'teacher':
        cursor.execute("SELECT student_id,date, status FROM attendance")
        attendance_records = cursor.fetchall()
    else:
        student_id = session.get('student_id')
        cursor.execute("SELECT student_id,date,status FROM attendance WHERE student_id = ?", (student_id,))
        attendance_records = cursor.fetchall()
    
    conn.close()
    return render_template('view_attendance.html', attendance_records=attendance_records)

# Generate QR code
@app.route('/generate_qr', methods=['GET', 'POST'])
def generate_qr():
    if 'role' in session and session['role'] == 'teacher':
        if request.method == 'POST':
            student_id = request.form.get('student_id')

            if not student_id:
                flash('Student ID is required!', 'danger')
                return redirect(url_for('generate_qr'))

            conn = init_db()
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM students WHERE student_id = ?", (student_id,))
            student = cursor.fetchone()
            conn.close()

            if student:
                name = student[0]
                qr_data = f"{student_id},{name}"
                qr_path = f'static/qr_codes/{student_id}.png'
                os.makedirs(os.path.dirname(qr_path), exist_ok=True)

                # Generate QR code
                qr = qrcode.make(qr_data)
                qr.save(qr_path)

                flash(f'QR code generated for {name}!', 'success')
                return render_template('show_qr.html', qr_path=qr_path, name=name)
            else:
                flash('Student not found. Please check the ID.', 'danger')
                return redirect(url_for('generate_qr'))

        return render_template('generate_qr.html')
    else:
        flash('Access denied. Only teachers can generate QR codes.', 'danger')
        return redirect(url_for('login'))

# Scan QR code with webcam
@app.route('/scan_qr', methods=['GET', 'POST'])
def scan_qr():
    if request.method == 'POST':
        cap = cv2.VideoCapture(0)
        detector = cv2.QRCodeDetector()

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            data, _, _ = detector.detectAndDecode(frame)
            if data:
                cap.release()
                cv2.destroyAllWindows()
                try:
                    student_id, name = data.split(',')
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

            cv2.imshow("Scan QR Code", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

        cap.release()
        cv2.destroyAllWindows()
    
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
            reset_token = hashlib.sha256(email.encode()).hexdigest()
            session['reset_email'] = email
            session['reset_token'] = reset_token

            flash(f'Password reset token: {reset_token[:10]}...', 'info')  # Simulate sending an email
            return redirect(url_for('reset_password'))
        else:
            flash('Email not found. Try again.', 'danger')

        conn.close()
    return render_template('forgot_password.html')
#reset password
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        # Use .get() to avoid KeyError
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        token = request.form.get('token')

        # Check if all fields are present
        if not email or not new_password or not token:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('reset_password'))

        conn = init_db()
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user and token == hashlib.sha256(email.encode()).hexdigest():
            hashed_password = hash_password(new_password)
            cursor.execute("UPDATE users SET password_hash = ? WHERE email = ?", (hashed_password, email))
            conn.commit()
            conn.close()
            flash('Password reset successful! You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid token or email. Please try again.', 'danger')
            conn.close()

    return render_template('reset_password.html')

@app.route('/export_attendance')
def export_attendance():
    if 'role' in session and session['role'] == 'teacher':
        conn = init_db()
        cursor = conn.cursor()

        # Fetch attendance data
        cursor.execute('''SELECT students.student_id, students.name, attendance.date, attendance.status
                          FROM attendance
                          JOIN students ON attendance.student_id = students.student_id
                          ORDER BY attendance.date''')
        
        records = cursor.fetchall()
        conn.close()

        if records:
            # Create DataFrame
            df = pd.DataFrame(records, columns=['Student ID', 'Name', 'Date', 'Status'])

            # Save to Excel
            excel_path = 'static/attendance_records.xlsx'
            df.to_excel(excel_path, index=False)

            flash('Attendance records exported successfully!', 'success')
            return redirect(url_for('download_attendance'))
        else:
            flash('No attendance records found.', 'warning')
            return redirect(url_for('dashboard'))
    else:
        flash('Access denied. Only teachers can export attendance.', 'danger')
        return redirect(url_for('login'))
    
@app.route('/download_attendance')
def download_attendance():
    return render_template('download_attendance.html')

@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    if 'role' in session and session['role'] == 'teacher':
        if request.method == 'POST':
            name = request.form['name']
            email = request.form['email']
            student_id = request.form['student_id']

            conn = init_db()
            cursor = conn.cursor()

            # Check if student already exists
            cursor.execute("SELECT * FROM students WHERE student_id = ?", (student_id,))
            existing_student = cursor.fetchone()

            if existing_student:
                flash('Student ID already exists. Try another ID.', 'danger')
            else:
                # Insert the new student
                cursor.execute("INSERT INTO students (name, email, student_id) VALUES (?, ?, ?)", 
                               (name, email, student_id))
                conn.commit()
                flash('Student added successfully!', 'success')

            conn.close()

        return render_template('add_student.html')
    else:
        flash('Access denied. Only teachers can add students.', 'danger')
        return redirect(url_for('login'))
#visualize the attendance
@app.route('/attendance_analytics')
def attendance_analytics():
    if 'teacher' in session:
        conn = init_db()
        df = pd.read_sql_query("SELECT student_id, date FROM attendance", conn)
        conn.close()
        
        if df.empty:
            flash('No attendance records found.', 'warning')
            return redirect(url_for('dashboard'))
        
        df['date'] = pd.to_datetime(df['date'])
        attendance_counts = df.groupby('id')['date'].count().reset_index()
        
        plt.figure(figsize=(10, 6))
        plt.bar(attendance_counts['id'], attendance_counts['date'])
        plt.xticks(rotation=45)
        plt.xlabel('Student')
        plt.ylabel('Attendance Count')
        plt.title('Student Attendance Overview')
        plt.tight_layout()
        analytics_path = 'static/attendance_chart.png'
        plt.savefig(analytics_path)
        plt.close()
        
        return render_template('attendance_analytics.html', chart_path=analytics_path)
    else:
        flash('Access denied. Only teachers can view analytics.', 'danger')
        return redirect(url_for('dashboard'))



if __name__ == '__main__':
    app.run(debug=True)
