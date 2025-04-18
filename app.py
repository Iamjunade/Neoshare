from flask import Flask, request, redirect, url_for, send_from_directory, render_template, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash

# Config
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'docx'}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.secret_key = 'supersecretkey'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create upload folder
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Fake "database" to store users (in a real app, use a real database)
users_db = {}

# Track downloads
downloads = {}

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

def allowed_file(filename):
    """Check if the file is allowed by extension and MIME type."""
    if '.' in filename:
        ext = filename.rsplit('.', 1)[1].lower()
        return ext in ALLOWED_EXTENSIONS
    return False

@login_manager.user_loader
def load_user(user_id):
    return users_db.get(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if user exists and password is correct
        user = next((user for user in users_db.values() if user.username == username), None)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Login successful", "success")
            return redirect(url_for('upload_file'))
        else:
            flash("Invalid username or password", "danger")
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if user already exists
        if username in [user.username for user in users_db.values()]:
            flash("Username already exists", "danger")
            return redirect(url_for('signup'))
        # Store new user in "database"
        password_hash = generate_password_hash(password)
        new_user = User(id=username, username=username, password_hash=password_hash)
        users_db[username] = new_user
        login_user(new_user)
        flash("Account created successfully", "success")
        return redirect(url_for('upload_file'))
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "info")
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(save_path):
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                filename = f"{timestamp}_{filename}"
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(save_path)
            flash(f'File "{filename}" uploaded successfully!', 'success')
            return redirect(url_for('upload_file'))
        else:
            flash('File type not allowed or file content is invalid', 'danger')
            return redirect(request.url)

    files_data = []
    for fname in os.listdir(UPLOAD_FOLDER):
        path = os.path.join(UPLOAD_FOLDER, fname)
        if os.path.isfile(path):
            size_kb = os.path.getsize(path) / 1024
            timestamp = datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M')
            count = downloads.get(fname, 0)
            files_data.append({'name': fname, 'size': f"{size_kb:.2f} KB", 'time': timestamp, 'downloads': count})
    return render_template('index.html', files=files_data)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    downloads[filename] = downloads.get(filename, 0) + 1
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)