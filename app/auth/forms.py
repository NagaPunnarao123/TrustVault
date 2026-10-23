from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from app.models import User

class LoginForm(FlaskForm):
    """Secure user login form."""
    email = StringField('Email Address', validators=[
        DataRequired(message="Email is required."),
        Email(message="Please enter a valid email address.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required.")
    ])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Sign In')


class RegisterForm(FlaskForm):
    """
    User registration form.
    Creates both the User and their Organization/Tenant.
    The registering user becomes the initial OWNER of their organization.
    Note: Self-registration as an ADMIN is strictly prohibited.
    """
    full_name = StringField('Full Name', validators=[
        DataRequired(message="Full name is required."),
        Length(min=2, max=100, message="Full name must be between 2 and 100 characters.")
    ])
    email = StringField('Email Address', validators=[
        DataRequired(message="Email is required."),
        Email(message="Please enter a valid email address."),
        Length(max=120)
    ])
    organization_name = StringField('Organization / Company Name', validators=[
        DataRequired(message="Organization name is required."),
        Length(min=2, max=100, message="Organization name must be between 2 and 100 characters.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=8, max=128, message="Password must be at least 8 characters long.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password."),
        EqualTo('password', message="Passwords must match.")
    ])
    submit = SubmitField('Create Account')

    def validate_email(self, field):
        """Prevent duplicate account registrations."""
        normalized_email = field.data.strip().lower()
        if User.query.filter_by(email=normalized_email).first():
            raise ValidationError('An account with this email address already exists.')


class ChangePasswordForm(FlaskForm):
    """Profile password update form."""
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message="Current password is required.")
    ])
    new_password = PasswordField('New Password', validators=[
        DataRequired(message="New password is required."),
        Length(min=8, max=128, message="New password must be at least 8 characters long.")
    ])
    confirm_new_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message="Please confirm your new password."),
        EqualTo('new_password', message="New passwords must match.")
    ])
    submit = SubmitField('Update Password')
