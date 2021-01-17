from flask import Flask
from flask import render_template, url_for, redirect, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectMultipleField, RadioField, IntegerField, SelectField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

app.config["DEBUG"] = True
app.config["SECRET_KEY"] = os.environ.get('FLASK_SECRET_KEY') # custom env variable
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///"+os.path.dirname(os.path.realpath(__file__))+"/database.db" # not included in the repo, for obvious reasons
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

lm = LoginManager()
lm.init_app(app)
lm.login_view = 'login'

#########################
# MODELS
#########################
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(16), unique=True)
    fullname = db.Column(db.String(64))
    email = db.Column(db.String(64), unique=True)
    acctype = db.Column(db.String(7))
    password = db.Column(db.String(80))

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bookname = db.Column(db.String(64))
    donor = db.Column(db.String(64))
    library = db.Column(db.String(64))
    libmail = db.Column(db.String(64))
    author = db.Column(db.String(64))
    publisher = db.Column(db.String(32))
    year = db.Column(db.Integer())

class UserDonation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bookname = db.Column(db.String(64))
    donor = db.Column(db.String(64))
    library = db.Column(db.String(64))
    author = db.Column(db.String(64))
    publisher = db.Column(db.String(32))
    year = db.Column(db.Integer())
    status = db.Column(db.String(16))
#########################
# choices = [choice for choice in db.session.query(User).filter(User.acctype=='library')]
#########################
# FORMS
#########################
class LoginForm(FlaskForm):
    user = StringField('Username', validators=[InputRequired(), Length(min=4, max=16)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=128)])
    remember = BooleanField('Remember me')

class RegisterForm(FlaskForm):
    user = StringField('Username', validators=[InputRequired(), Length(min=4, max=32)])
    fullname = StringField('Full Name', validators=[InputRequired(), Length(min=3, max=32)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=64)])
    acctype = RadioField('Account type', choices=[('user','User'),('library','Library')], validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=128)])

class AddBook(FlaskForm):
    bookname = StringField('Book Name', validators=[InputRequired(), Length(min=4, max=64)])
    donor = StringField('Donor', validators=[InputRequired(), Length(min=3, max=64)])
    author = StringField('Author', validators=[InputRequired(), Length(min=3, max=64)])
    publisher = StringField('Publisher', validators=[InputRequired(), Length(min=3, max=32)])
    year = IntegerField('Year', validators=[InputRequired()])

class DonateBook(FlaskForm):
    bookname = StringField('Book Name', validators=[InputRequired(), Length(min=4, max=64)])
    library = SelectField('Library', coerce=str, validators=[InputRequired()])
    author = StringField('Author', validators=[InputRequired(), Length(min=3, max=64)])
    publisher = StringField('Publisher', validators=[InputRequired(), Length(min=3, max=32)])
    year = IntegerField('Year', validators=[InputRequired()])

# class DonateReqs(FlaskForm):
#     bookname = StringField('Book Name', validators=[InputRequired(), Length(min=4, max=64)])
#     author = StringField('Author', validators=[InputRequired(), Length(min=3, max=64)])
#     publisher = StringField('Publisher', validators=[InputRequired(), Length(min=3, max=32)])
#     year = IntegerField('Year', validators=[InputRequired()])

#########################

#########################
# ROUTES
#########################

@lm.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET','POST'])
def home():
    loginform = LoginForm()
    regform = RegisterForm()
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html', loginform=loginform, regform=regform)

@app.route('/login', methods=['GET','POST'])
def login():
    regform = RegisterForm()
    loginform = LoginForm()
    bookform = AddBook()
    donateform = DonateBook()

    if loginform.validate_on_submit():
        user = User.query.filter_by(username=loginform.user.data).first()
        if user:
            if check_password_hash(user.password, loginform.password.data):
                print(type(loginform.remember.data))
                login_user(user, remember=loginform.remember.data)
                return redirect(url_for('dashboard'))

    return render_template('login.html', loginform=loginform, regform=regform, bookform=bookform, donateform=donateform)

@app.route('/register', methods=['GET','POST'])
def register():
    regform = RegisterForm()
    loginform = LoginForm()
    bookform = AddBook()
    donateform = DonateBook()

    if regform.validate_on_submit():
        new_user = User(username=regform.user.data,
            fullname=regform.fullname.data,
            email=regform.email.data,
            acctype=regform.acctype.data,
            password=generate_password_hash(regform.password.data, method='sha256'))
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', regform=regform, loginform=loginform, bookform=bookform, donateform=donateform)

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    bookshelf = None
    donations = None
    books = None
    donations = None

    if current_user.acctype == 'library':
        bookshelf = db.session.query(Book).filter(Book.library==current_user.username)
        donations = db.session.query(UserDonation).filter(UserDonation.library==current_user.username)
        print(donations)
    elif current_user.acctype == 'user':
        books = db.session.query(Book)
        donations = db.session.query(UserDonation).filter(UserDonation.donor==current_user.username)
        print(books)
        
    loginform = LoginForm()
    regform = RegisterForm()
    bookform = AddBook()
    donateform = DonateBook()
    donateform.library.choices = [(lib.username, lib.fullname) for lib in User.query.filter_by(acctype='library').order_by('fullname')]

    return render_template('dashboard.html', regform=regform, loginform=loginform, bookform=bookform,  donateform=donateform, bookshelf=bookshelf, books=books, donations=donations)

@app.route('/profile', methods=['GET','POST'])
def profile():
    return render_template('profile.html')

@app.route('/findbook', methods=['GET','POST'])
def findbook():
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['GET','POST'])
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/addbook', methods=['GET','POST'])
def addbook():
    bookform = AddBook()

    new_book = Book(bookname=bookform.bookname.data,
        author=bookform.author.data,
        donor=bookform.donor.data,
        library=current_user.username,
        libmail=current_user.email,
        publisher=bookform.publisher.data,
        year=bookform.year.data)

    if bookform.validate_on_submit():
        db.session.add(new_book)
        db.session.commit()

    return redirect(url_for('dashboard')+'#find-book-list')

@app.route('/donatebook', methods=['GET','POST'])
def donatebook():
    donateform = DonateBook()
    donateform.library.choices = [(lib.username, lib.fullname) for lib in User.query.filter_by(acctype='library').order_by('fullname')]

    print(donateform.validate_on_submit())
    if donateform.validate_on_submit():
        new_donation = UserDonation(bookname=donateform.bookname.data,
            author=donateform.author.data,
            donor=current_user.username,
            library=donateform.library.data,
            publisher=donateform.publisher.data,
            year=donateform.year.data,
            status='pending')

        db.session.add(new_donation)
        db.session.commit()

    if donateform.errors:
        print(donateform.errors)
        print(type(donateform.year.data))

    return redirect(url_for('dashboard')+'#donate-book-list')

@app.route('/canceldonate', methods=['GET','POST'])
def canceldonate():
    
    return redirect(url_for('dashboard'))

port = os.environ.get('PORT', 5000)
if __name__ == '__main__':
    app.run(threaded=True, port=port)
