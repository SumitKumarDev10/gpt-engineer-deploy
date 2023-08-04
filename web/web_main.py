from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, ValidationError
from wtforms.validators import Email
from sqlalchemy.orm import Session
from datetime import datetime
from sqlalchemy import desc  # Add this import to enable sorting in descending order
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = 'kumar1234'  # Replace with a secure secret key
db = SQLAlchemy(app)
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
login_manager.login_view = 'login_page'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

''' # Put This code when getting warning

LegacyAPIWarning: The Query.get() method is considered legacy as of the 1.x series of SQLAlchemy and becomes a legacy construct in 2.0. The method is now available as Session.get() (deprecated since: 2.0) (Background on SQLAlchemy 2.0 at: https://sqlalche.me/e/b8d9)
  return User.query.get(int(user_id))

@login_manager.user_loader
def load_user(user_id):
    # Use Session.get() instead of Query.get()
    with app.app_context():
        return db.session.get(int(user_id))'''

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # New column for date and time of creation
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('posts', lazy=True))
class LoginForm(FlaskForm):
    username_or_email = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

    def validate_username_or_email(self, field):
        input_value = field.data
        user = User.query.filter((User.username == input_value) | (User.email == input_value)).first()

        if not user:
            raise ValidationError('Invalid username or email.')

        self.user = user
    
    def validate_password(self, field):
        input_password = field.data

        if not hasattr(self, 'user'):
            raise ValidationError('Please provide a valid username or email first.')

        user = self.user

        if not user.check_password(input_password):
            raise ValidationError('Invalid password.')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        user = User.query.filter_by(email=field.data).first()
        if user:
            raise ValidationError('Email is already registered.')

    def validate_username(self, field):
        user = User.query.filter_by(username=field.data).first()
        if user:
            raise ValidationError('Username is already taken.')

class CreateBlogForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Create Blog Post')

@app.route('/')
def home_page():
    return render_template('index.html')

@app.route('/aboutus')
def aboutus_page():
    return render_template('aboutus.html')

@app.route('/gettingstarted')
def gettingstarted_page():
    return render_template('gettingstarted.html')

@app.route('/documentation')
def documentation_page():
    return render_template('documentation.html')

@app.route('/community')
def community_page():
    return render_template('community.html')

"""
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Look up the user by email in the database
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            # If the user exists and the password is correct, log them in
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home_page'))
        else:
            failure_message = 'Failed To Login:Invalid email or password'
            redirect_url = url_for('login_page')
            return redirect(url_for('failure_page', message=failure_message, redirect_url=redirect_url))
    return render_template('login.html')
"""
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    print(current_user)
    form = LoginForm()

    if form.validate_on_submit():
        email_or_username = form.username_or_email.data
        password = form.password.data

        user = form.user

        if user and user.check_password(password):
            # If the user exists and the password is correct, log them in
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home_page'))
        else:
            failure_message = 'Failed To Login:Invalid email or password'
            redirect_url = url_for('login_page')
            return redirect(url_for('failure_page', message=failure_message, redirect_url=redirect_url))

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegistrationForm()

    if form.validate_on_submit():
        email = form.email.data
        username = form.username.data
        password = form.password.data

        new_user = User(email=email, username=username)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login_page'))

    return render_template('register.html', form=form)

@app.route('/show-data')
def show_data_page():
    # Query the database to retrieve all users and blog posts
    users = User.query.all()
    blog_posts = BlogPost.query.all()

    # Render the HTML template and pass the user and blog post data to it
    return render_template('show_data.html', users=users, blog_posts=blog_posts)

# Blog Pages
@app.route('/blog')
def blog_page():
    # Query the database to retrieve all blog posts and sort them based on the created_at field in descending order
    blog_posts = BlogPost.query.order_by(desc(BlogPost.created_at)).all()

    # Render the HTML template and pass the blog posts data to it
    return render_template('blog.html', blog_posts=blog_posts)

@app.route('/failure/<message>/<redirect_url>')
def failure_page(message, redirect_url):
    m = message.split(':')
    message = {'title': m[0], 'message': m[1]} # 'Invalid email or password'
    return render_template('failure.html', message=message, redirect_url=redirect_url)

@app.route('/create-blog', methods=['GET', 'POST'])
@login_required
def create_blog_page():
    form = CreateBlogForm()

    if request.method == 'POST' and form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        # Set the date and time of creation
        created_at = datetime.utcnow()

        # Create a new blog post using the form data, the current user, and the created_at date
        new_post = BlogPost(title=title, content=content, user=current_user, created_at=created_at)

        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('home_page'))
    
    return render_template('createblog.html', form=form)

@app.route('/blog/<int:post_id>')
def blog_post_page(post_id):
    # Query the database to retrieve the blog post with the given post_id
    post = BlogPost.query.get_or_404(post_id)

    # Render the HTML template and pass the blog post data to it
    return render_template('blogpost.html', post=post)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    print(current_user)
    return redirect(url_for('home_page'))


if __name__ == '__main__':
    # Create the database tables if needed
    with app.app_context():
        db.create_all()

    # Get the port number from the environment variable 'PORT', or use 5000 as default
    port = int(os.environ.get("PORT", 5000))

    # Start the Flask development server
    app.run(debug=True, host='0.0.0.0', port=port)
