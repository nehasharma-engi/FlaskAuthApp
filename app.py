from flask import Flask, render_template, redirect, request, session, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'secret_key'

db = SQLAlchemy(app)

# ✅ USER MODEL
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        # 🔐 Hash password
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


# ✅ CREATE DB
with app.app_context():
    db.create_all()


# ✅ HOME
@app.route('/')
def home():
    return render_template('index.html')


# ✅ LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # 🔴 VALIDATION
        if not email or not password:
            flash("All fields are required!", "error")
            return redirect('/login')

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("User not found!", "error")
            return redirect('/login')

        if not user.check_password(password):
            flash("Incorrect password!", "error")
            return redirect('/login')

        # ✅ SUCCESS
        session['email'] = user.email
        flash("Login successful!", "success")
        return redirect('/dashboard')

    return render_template("login.html")


# ✅ REGISTER (FIXED AS PER REQUIREMENTS)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        # 🔴 1. EMPTY VALIDATION
        if not name or not email or not password:
            flash("All fields are required!", "error")
            return redirect('/register')

        # 🔴 2. PASSWORD LENGTH
        if len(password) < 6:
            flash("Password must be at least 6 characters!", "error")
            return redirect('/register')

        # 🔴 3. EMAIL UNIQUE CHECK
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered!", "error")
            return redirect('/register')

        # ✅ SAVE USER
        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please login.", "success")
        return redirect('/login')

    return render_template("register.html")


# ✅ DASHBOARD
@app.route("/dashboard")
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        return render_template("dashboard.html", user=user)

    flash("Please login first!", "error")
    return redirect('/login')


# ✅ LOGOUT
@app.route('/logout')
def logout():
    session.pop('email', None)
    flash("Logged out successfully!", "success")
    return redirect('/login')


# ✅ RUN
if __name__ == '__main__':
    app.run(debug=True)