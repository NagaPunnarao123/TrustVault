from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length

class AddTenantUserForm(FlaskForm):
    """Admin form to add or invite a user into the current organization."""
    email = StringField('Email Address', validators=[
        DataRequired(message="Email is required."),
        Email(message="Please enter a valid email address.")
    ])
    full_name = StringField('Full Name', validators=[
        DataRequired(message="Full name is required."),
        Length(min=2, max=100)
    ])
    role = SelectField('Assigned Role', choices=[
        ('VIEWER', 'VIEWER (Read-only access to shared documents)'),
        ('OWNER', 'OWNER (Upload and manage own documents)'),
        ('ADMIN', 'ADMIN (Manage organization users and audit logs)')
    ], default='VIEWER')
    submit = SubmitField('Add Member')
