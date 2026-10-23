from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length

class DocumentUploadForm(FlaskForm):
    """Secure document upload form."""
    file = FileField('Select Document', validators=[
        FileRequired(message="Please choose a file to upload.")
    ])
    category = SelectField('Category', choices=[
        ('General', 'General'),
        ('Financial', 'Financial'),
        ('Legal', 'Legal'),
        ('Technical', 'Technical'),
        ('HR', 'Human Resources'),
        ('Confidential', 'Confidential')
    ], default='General')
    description = TextAreaField('Description', validators=[
        Length(max=500, message="Description must be 500 characters or fewer.")
    ])
    submit = SubmitField('Upload Document')


class ShareDocumentForm(FlaskForm):
    """Grant document access to a colleague within the same organization."""
    recipient_email = StringField('Colleague Email Address', validators=[
        DataRequired(message="Recipient email is required."),
        Email(message="Please enter a valid email address.")
    ])
    submit = SubmitField('Grant Access')
