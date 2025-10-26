import os
import re
import io
import csv
from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from fpdf import FPDF

# --- App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-very-secret-and-secure-key-that-you-should-change'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login page if user is not authenticated

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    history_logs = db.relationship('HistoryLog', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class HistoryLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request = db.Column(db.String(300), nullable=False)
    result = db.Column(db.String(300), nullable=False)
    status = db.Column(db.String(10), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --- Validation Logic ---
def validate_http_request_line(line):
    parts = line.split()
    if len(parts) != 3:
        return False, "Invalid Format: Must have three parts."
    method, uri, version = parts
    if not method.isalpha() or not method.isupper():
        return False, "Error: Method must be uppercase."
    if not uri.startswith('/'):
        return False, "Error: URI must start with '/'."
    if not re.match(r'^HTTP/\d\.\d$', version):
        return False, "Error: Invalid version format."
    return True, "Success: The HTTP request line format is valid."


# --- Routes ---
@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
        else:
            new_user = User(username=username)
            new_user.set_password(request.form.get('password'))
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    result, status, request_data = "", "", ""
    if request.method == 'POST':
        request_data = request.form.get('request_data', '')
        first_line = request_data.split('\n')[0].strip()
        if first_line:
            is_valid, result = validate_http_request_line(first_line)
            status = "success" if is_valid else "error"
            new_log = HistoryLog(
                request=first_line, result=result, status=status,
                time=datetime.now().strftime("%I:%M:%S %p"),
                author=current_user
            )
            db.session.add(new_log)
            db.session.commit()

    user_history = HistoryLog.query.filter_by(user_id=current_user.id).order_by(HistoryLog.id.desc()).all()
    return render_template('index.html', result=result, status=status, request_data=request_data, history=user_history)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/download/csv')
@login_required
def download_csv():
    user_history = HistoryLog.query.filter_by(user_id=current_user.id).order_by(HistoryLog.id.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Request Line', 'Result', 'Time'])
    for item in user_history:
        writer.writerow([item.request, item.result, item.time])
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=history.csv"})


@app.route('/download/pdf')
@login_required
def download_pdf():
    user_history = HistoryLog.query.filter_by(user_id=current_user.id).order_by(HistoryLog.id.desc()).all()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(0, 10, "HTTP Validation History", ln=True, align='C')

    # --- Table headers ---
    pdf.set_font("Arial", "B", 10)
    pdf.cell(85, 10, 'Request Line', border=1)
    pdf.cell(75, 10, 'Result', border=1)
    pdf.cell(30, 10, 'Time', border=1, ln=True)

    pdf.set_font("Arial", size=8)
    for item in user_history:
        if pdf.get_y() > 270:
            pdf.add_page()
        pdf.multi_cell(85, 10, item.request, border=1, new_x="RIGHT", new_y="TOP")
        pdf.multi_cell(75, 10, item.result, border=1, new_x="RIGHT", new_y="TOP")
        pdf.multi_cell(30, 10, item.time, border=1, new_x="RIGHT", new_y="TOP", ln=True)

    return Response(
        pdf.output(dest='S').encode('latin-1', 'ignore'),
        mimetype='application/pdf',
        headers={'Content-Disposition': 'attachment;filename=history.pdf'}
    )


if __name__ == '__main__':
    instance_path = os.path.join(basedir, 'instance')
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
