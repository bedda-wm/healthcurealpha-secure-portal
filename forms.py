from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])
    role = SelectField("Role", choices=[("staff", "Staff"), ("admin", "Admin")], default="staff")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])

class PatientForm(FlaskForm):
    patient_name = StringField("Patient Name", validators=[DataRequired(), Length(min=2, max=120)])
    diagnosis = StringField("Diagnosis", validators=[DataRequired(), Length(min=2, max=255)])
    notes = TextAreaField("Notes (optional)")
