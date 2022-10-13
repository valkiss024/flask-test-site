from flask import Flask, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, EmailField, TelField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError, StopValidation

app = Flask(__name__)  # Instantiate Flask object - app
app.config['SECRET_KEY'] = 'secret'  # Encrypted key to access session ID(linking the user to the server side)

# Setup DB connection (SQLite used for simple testing (local storage) - MYSql or Mongo implementation for production)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'  # Configure the database endpoint
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Create the database instance
db = SQLAlchemy(app)

# Create login manager to handle authentication / sessions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    org = Organization.query.filter_by(id=user_id).first()
    if (not user and not org):
        return None
    return org if org else user


# Create the user table in the db
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(40), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    contact_number = db.Column(db.String(13), nullable=True)
    password = db.Column(db.String(120), nullable=False)

    def __init__(self, first_name, last_name, email, contact_number):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.contact_number = contact_number

    def __repr__(self):
        return f'User({self.first_name}, {self.last_name}, {self.email}, {self.contact_number})'

    def create_password_hash(self, password):
        self.password = generate_password_hash(password=password)

    def validate_password_hash(self, password):
        return check_password_hash(pwhash=self.password, password=password)


class Organization(db.Model, UserMixin):
    __tablename__ = 'organizations'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    location = db.Column(db.String(120), nullable=False)  # country/city/etc..
    approved = db.Column(db.Boolean, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __init__(self, name, email, location):
        self.name = name
        self.email = email
        self.location = location
        self.approved = False  # All new orgs created not approved

    def __repr__(self):
        return f'Organization({self.name}, {self.email}, {self.location}, {self.approved})'

    def create_password_hash(self, password):
        self.password = generate_password_hash(password=password)

    def validate_password_hash(self, password):
        return check_password_hash(pwhash=self.password, password=password)


with app.app_context():
    # db.drop_all()
    db.create_all()
    db.session.commit()


class OrganisationRegisterForm(FlaskForm):
    name = StringField(label='Organisation Name:', validators=[InputRequired(), Length(min=1, max=40)])
    email_address = EmailField(label='Email Address:', validators=[InputRequired(), Email(), Length(max=120)])
    location = StringField(label='Location:', validators=[InputRequired(), Length(min=1, max=40)])
    # TODO: Add country/city/street/num/post code??
    password = PasswordField(label='Password:', validators=[InputRequired(), Length(min=8, max=40)])
    confirm_password = PasswordField(label='Confirm Password:', validators=[InputRequired(), Length(min=8, max=40)])
    submit = SubmitField('Register')

    # TODO: How to validated new organisation registration request? email / name / location unique??

    def validate_confirm_password(self, confirm_password):
        if confirm_password.data != self.password.data:
            raise ValidationError('Passwords must match!')


class UserRegisterForm(FlaskForm):
    first_name = StringField(label='First Name:', validators=[InputRequired(), Length(min=1, max=40)],
                             render_kw={'placeholder': 'Enter First Name'})
    last_name = StringField(validators=[InputRequired(), Length(min=1, max=40)],
                            render_kw={'placeholder': 'Last Name'})
    email_address = EmailField(validators=[InputRequired(), Email(), Length(max=120)],
                               render_kw={'placeholder': 'Email Address'})
    contact_number = TelField(validators=[Length(max=13)], render_kw={'placeholder': 'Contact Number'})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=40)],
                             render_kw={'placeholder': 'Password'})
    # TODO: randomly generated password for user creation ??
    submit = SubmitField('Register')

    def validate_email_address(self, email_address):
        existing_user = User.query.filter_by(email=email_address.data).first()
        print(existing_user)
        if existing_user:
            raise ValidationError('Email already exists!')


class LoginForm(FlaskForm):
    email = EmailField(validators=[InputRequired(), Email(), Length(max=120)],
                       render_kw={'placeholder': 'Email Address'})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=40)],
                             render_kw={'placeholder': 'Password'})
    submit = SubmitField('Login')

    def validate_email(self, email):
        user = Organization.query.filter_by(email=email.data).first()
        print(user)
        if not user:
            raise ValidationError('Email address doesn\'t exists!')

    def validate_password(self, password):
        user = Organization.query.filter_by(email=self.email.data).first()
        if user:
            if not user.validate_password_hash(password.data):
                raise ValidationError('Incorrect password!')


# Create endpoints
@app.route('/', methods=['GET', 'POST'])  # Home route
@app.route('/login', methods=['GET', 'POST'])  # Login route
def login():
    """This endpoint handles the logic for logging users in to see dashboard"""
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = Organization.query.filter_by(email=login_form.email.data).first()
        if user and user.validate_password_hash(login_form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))

    return render_template('login.html', form=login_form)


@app.route('/signup', methods=['GET', 'POST'])
def register():
    """This endpoint handles the logic for creating new users"""
    # register_form = UserRegisterForm()  # Create a registration form instance
    register_form = OrganisationRegisterForm()
    if register_form.validate_on_submit():
        # Create the new User object
        new_org = Organization(
            name = register_form.name.data,
            email = register_form.email_address.data,
            location = register_form.location.data
        )

        new_org.create_password_hash(register_form.password.data)
        db.session.add(new_org)

        """new_user = User(
            first_name=register_form.first_name.data,
            last_name=register_form.last_name.data,
            email=register_form.email_address.data,
            contact_number=register_form.contact_number.data
        )
        # Add the hashed password to the user object
        new_user.create_password_hash(register_form.password.data)
        # Save the user to the database
        db.session.add(new_user)"""
        db.session.commit()
        # Redirect the user to the login page
        # flash('Account created successfully!')
        flash('Account has been registered successfully, please wait for approval!')
        return redirect(url_for('login'))
    return render_template('register_org.html', form=register_form)


@app.route('/dashboard')
@login_required  # Only accessible if the user if logged in
def dashboard():
    return render_template('dashboard.html', user=current_user)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
