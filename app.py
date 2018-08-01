from flask import Flask, render_template, redirect, url_for, g, session, flash, request
from flask_session import Session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from datetime import datetime
from wtforms import StringField, PasswordField, BooleanField, DateTimeField, TextField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = "ASNDASNDASONDSAOIDMAODNAS"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////Users/michaelaronian/Desktop/FlaskProject/database.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True)
    firstname = db.Column(db.String(15))
    lastname = db.Column(db.String(15))
    birthday = db.Column(db.DateTime)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(25))
    title = db.Column(db.String(100))
    content = db.Column(db.Text)

class BlogPost(db.model):
    id = db.Column(db.Integer, primary_key=True)
    title = StringField('Title', validators=[InputRequired()])
    content = TextField('Post', validators=[InputRequired()])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=25)])
    firstname = StringField('First Name', validators=[InputRequired(), Length(min=1, max=15)])
    lastname = StringField('Last Name', validators=[InputRequired(), Length(min=1, max=15)])
    birthday = DateTimeField('Birthday', validators=[InputRequired()], format="%m/%d/%Y")
    email = StringField('Email Address', validators=[InputRequired(), Length(min=6, max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=25)])



class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    remember = BooleanField('Remember Me')

class GameForm(FlaskForm):
    color = StringField('Color', validators=[InputRequired(), Length(min=1, max=20)])


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hash_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username  = form.username.data,
                        firstname = form.firstname.data,
                        lastname  = form.lastname.data,
                        birthday  = form.birthday.data,
                        email     = form.email.data,
                        password=hash_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Congrats, you are registered!")
        return redirect(url_for('index'))

    return render_template('register.html', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    r_form = RegistrationForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('profile', username=form.username.data))
            else:
                flash("User or Password Doesn't Exist")
        else:
            flash("User or Password Doesn't Exist")

    return render_template('login.html', form=form)

@app.route("/profile/<username>", methods=['GET', 'POST'])
@login_required
def profile(username):
    return render_template('profile.html', username=username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/games', methods=['GET', 'POST'])
@login_required
def games():
    import random
    form= GameForm()
    color = ["green","blue","yellow","red",'purple']
    computer = random.choice(color)
    return render_template('games.html', form=form,computer=computer )


@app.route('/gamesone', methods=['GET', 'POST'])
@login_required
def gamesone():
    import random
    form = GameForm()
    color = ["green","blue","yellow","red",'purple']
    computer = random.choice(color)
    return render_template('gamesone.html', form=form, computer=computer )

@app.route('/addpost',methods=['GET', 'POST'] )
@login_required
def addpost():
    blogform = BlogPost()

    if blogform.validate_on_submit():
        new_post = User(title  = form.title.data,
                        content = form.content.data)
        db.session.add(new_post)
        db.session.commit()
        flash("Post Saved")


    return render_template('blog.html', form=blogform)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=4400)
