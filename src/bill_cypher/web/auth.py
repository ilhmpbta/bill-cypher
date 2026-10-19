import argon2
from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import login_required, login_user, logout_user

from ..db import create_user, get_user_by_username
from .forms import LoginForm, RegisterForm
from .models import User

bp = Blueprint("auth", __name__, url_prefix="/auth")
ph = argon2.PasswordHasher()


@bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.username.data is None or form.password.data is None:
            flash("Username and password are required.", "danger")
            return render_template("register.html", form=form)
        username = form.username.data
        password = form.password.data

        existing = get_user_by_username(username)
        if existing:
            flash("Username already exists.", "danger")
            return render_template("register.html", form=form)

        password_hash = ph.hash(password)
        create_user(username, password_hash)
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if form.username.data is None or form.password.data is None:
            flash("Username and password are required.", "danger")
            return render_template("login.html", form=form)
        username = form.username.data
        password = form.password.data

        row = get_user_by_username(username)
        if row is None:
            flash("Invalid username or password.", "danger")
            return render_template("login.html", form=form)

        try:
            ph.verify(row["password_hash"], password)
        except argon2.exceptions.VerifyMismatchError:
            flash("Invalid username or password.", "danger")
            return render_template("login.html", form=form)

        user = User(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
        )
        login_user(user)
        flash("Logged in successfully.", "success")
        return redirect(url_for("auth.login"))

    return render_template("login.html", form=form)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("auth.login"))
