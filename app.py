from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, PatientRecord
from forms import RegisterForm, LoginForm, PatientForm
from security import hash_password, verify_password
from flask_wtf.csrf import CSRFProtect
import os


def create_app():
    app = Flask(__name__)

    csrf = CSRFProtect(app)

    app.config["SECRET_KEY"] = os.urandom(32)

    # SQLite DB file will be created in project folder
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///healthcurealpha.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Cookie/session hardening (good for report)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    def require_admin():
        if not current_user.is_authenticated or current_user.role != "admin":
            return False
        if not current_user.is_active:
            return False
        return True

    @app.before_request
    def block_inactive_users():
        if current_user.is_authenticated and not current_user.is_active:
            logout_user()
            flash("Your account is disabled. Contact an administrator.", "warning")
            return redirect(url_for("login"))

    @app.route("/")
    def home():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        form = RegisterForm()

        # Check if at least one admin already exists (bootstrap logic)
        admin_exists = User.query.filter_by(role="admin").count() > 0

        if form.validate_on_submit():
            username = form.username.data.strip()

            # Prevent duplicate usernames
            if User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
                return render_template(
                    "register.html",
                    form=form,
                    admin_exists=admin_exists
                )

            # ROLE ASSIGNMENT RULES:
            # - If no admin exists yet → allow first admin (bootstrap)
            # - If admin exists → force all new registrations to staff
            if admin_exists:
                role = "staff"
            else:
                role = form.role.data  # first user can choose admin

            new_user = User(
                username=username,
                password_hash=hash_password(form.password.data),
                role=role,
                is_active=True
            )

            db.session.add(new_user)
            db.session.commit()

            flash("Account created successfully. You can now log in.", "success")
            return redirect(url_for("login"))

        return render_template(
            "register.html",
            form=form,
            admin_exists=admin_exists
        )



    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()

        if form.validate_on_submit():
            username = form.username.data.strip()
            user = User.query.filter_by(username=username).first()

            # Avoid leaking whether user exists (basic)
            if not user or not verify_password(form.password.data, user.password_hash):
                flash("Invalid username or password.", "danger")
                return render_template("login.html", form=form)

            if not user.is_active:
                flash("Your account is disabled. Contact an administrator.", "warning")
                return render_template("login.html", form=form)

            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))

        return render_template("login.html", form=form)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/patients", methods=["GET", "POST"])
    @login_required
    def patients():
        form = PatientForm()

        if form.validate_on_submit():
            record = PatientRecord(
                patient_name=form.patient_name.data.strip(),
                diagnosis=form.diagnosis.data.strip(),
                notes=(form.notes.data or "").strip(),
                created_by_user_id=current_user.id
            )
            db.session.add(record)
            db.session.commit()
            flash("Patient record added.", "success")
            return redirect(url_for("patients"))

        records = PatientRecord.query.order_by(PatientRecord.created_at.desc()).all()
        return render_template("patients.html", form=form, records=records)

    @app.route("/admin/users")
    @login_required
    def admin_users():
        if not require_admin():
            return render_template("forbidden.html"), 403

        users = User.query.order_by(User.created_at.desc()).all()
        return render_template("admin_users.html", users=users)

    @app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
    @login_required
    def toggle_user(user_id):
        if not require_admin():
            return render_template("forbidden.html"), 403

        if current_user.id == user_id:
            flash("You cannot disable your own account.", "warning")
            return redirect(url_for("admin_users"))

        user = User.query.get_or_404(user_id)
        user.is_active = not user.is_active
        db.session.commit()

        flash(f"User '{user.username}' is now {'active' if user.is_active else 'disabled'}.", "success")
        return redirect(url_for("admin_users"))
    
    @app.route("/admin/users/<int:user_id>/toggle_role", methods=["POST"])
    @login_required
    def toggle_role(user_id):
        if not require_admin():
            return render_template("forbidden.html"), 403

        # Prevent admin from changing their own role
        if current_user.id == user_id:
            flash("You cannot change your own role.", "warning")
            return redirect(url_for("admin_users"))

        user = User.query.get_or_404(user_id)

        # Toggle role
        if user.role == "admin":
            user.role = "staff"
        else:
            user.role = "admin"

        db.session.commit()

        flash(f"User '{user.username}' role changed to {user.role}.", "success")
        return redirect(url_for("admin_users"))


    @app.errorhandler(403)
    def forbidden(_):
        return render_template("forbidden.html"), 403

    @app.errorhandler(404)
    def not_found(_):
        return "Not Found", 404

    # Create tables on first run
    with app.app_context():
        db.create_all()

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
