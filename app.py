from flask import Flask, flash, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import check_password_hash, generate_password_hash
from forms import LoginForm, RegistrationForm  # Assuming you've defined LoginForm and RegistrationForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secure_secret_key'  # Replace with a securely generated key

# Initialize the database
def init_db():
    conn = sqlite3.connect('theatre_booking.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        movie_title TEXT NOT NULL,
        showtime TEXT NOT NULL,
        seats INTEGER NOT NULL
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

# Custom login function
def login_user(user_id):
    session['user_id'] = user_id

# Custom logout function
def logout_user():
    session.pop('user_id', None)

# Helper function to check if a user is logged in
def is_authenticated():
    return 'user_id' in session

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = sqlite3.connect('theatre_booking.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (form.username.data,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], form.password.data):
            login_user(user[0])  # Store user_id in the session
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)
        
        # Insert new user into the database
        conn = sqlite3.connect('theatre_booking.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different username.', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html', form=form)

@app.route('/')
def index():
    if not is_authenticated():
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('theatre_booking.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM bookings')
    bookings = cursor.fetchall()
    conn.close()
    return render_template('index.html', bookings=bookings)

@app.route('/create', methods=['GET', 'POST'])
def create():
    if not is_authenticated():
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        movie_title = request.form['movie_title']
        showtime = request.form['showtime']
        seats = request.form['seats']

        conn = sqlite3.connect('theatre_booking.db')
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO bookings (name, email, movie_title, showtime, seats)
        VALUES (?, ?, ?, ?, ?)
        ''', (name, email, movie_title, showtime, seats))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))

    return render_template('create.html')

@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    if not is_authenticated():
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('theatre_booking.db')
    cursor = conn.cursor()
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        movie_title = request.form['movie_title']
        showtime = request.form['showtime']
        seats = request.form['seats']

        cursor.execute('''
        UPDATE bookings
        SET name=?, email=?, movie_title=?, showtime=?, seats=?
        WHERE id=?
        ''', (name, email, movie_title, showtime, seats, id))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    
    cursor.execute('SELECT * FROM bookings WHERE id = ?', (id,))
    booking = cursor.fetchone()
    conn.close()
    return render_template('update.html', booking=booking)

@app.route('/delete/<int:id>', methods=['GET', 'POST'])
def delete(id):
    if not is_authenticated():
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('theatre_booking.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM bookings WHERE id = ?', (id,))
    booking = cursor.fetchone()
    if request.method == 'POST':
        cursor.execute('DELETE FROM bookings WHERE id = ?', (id,))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))

    conn.close()
    return render_template('delete.html', booking=booking)

if __name__ == '__main__':
    init_db()  # Create the database when the app starts
    app.run(debug=True)
