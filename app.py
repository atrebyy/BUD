import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functions import login_required, is_strong_password, usd
import secrets

# Configure application
app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(16)

# Auto reload template files
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_TYPE"] = "filesystem"

# Set session lifetime to one hour
app.config["SESSION_PERMANENT"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///bud.db")

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        return redirect("/register")
    
    if "username" in session:
        return redirect("/dashboard")
    
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        middle_name = request.form.get("middle_name")
        last_name = request.form.get("last_name")
        username = request.form.get("username")
        email = request.form.get("email")
        email_confirmation = request.form.get("email_confirmation")
        password = request.form.get("password")
        password_confirmation = request.form.get("password_confirmation")

        if not first_name or not last_name or not username or not email or not email_confirmation or not password or not password_confirmation:
            flash("Please fill all required fields.")
            return redirect("/register")
        
        existing_user = db.execute("SELECT * FROM user_profile WHERE username = ? OR email = ?;", username, email)
        if existing_user:
            if username == existing_user[0]["username"]:
                flash("Username already exists.")
                return redirect("/register")
            
            if email == existing_user[0]["email"]:
                flash("Email already exists.")
                return redirect("/register")
            
        if email != email_confirmation:
            flash("Emails do not match.")
            return redirect("/register")
        
        if not is_strong_password(password):
            flash("Your password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one digit, and one special character.")
            return redirect("/register")

        if password!= password_confirmation:
            flash("The passwords do not match.")
            return redirect("/register")

        db.execute("INSERT INTO user_profile (first_name, middle_name, last_name, username, email, password_hash) VALUES (?, ?, ?, ?, ?, ?);", first_name, middle_name, last_name, username, email, generate_password_hash(password, method="sha256"))
        session["username"] = username

        flash(f"Welcome {first_name}.")
        return redirect("/dashboard")
    
    if "username" in session:
        return redirect("/dashboard")
    
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if not username or not password:
            flash("Please fill all required fields.")
            return redirect("/login")
        
        user = db.execute("SELECT * FROM user_profile WHERE username = ?", username)
        if not user or not check_password_hash(user[0]["password_hash"], password) :
            flash("Invalid username or password.")
            return redirect("/login")
        
        session["username"] = username
        name = user[0]["first_name"]

        flash(f"Welcome back {name}.")
        return redirect("/dashboard")
    
    return render_template("login.html") 

@login_required
@app.route("/logout")
def logout():
    session.clear()
    flash("logged out.")
    return redirect("/login")

@login_required
@app.route("/delete", methods=["GET", "POST"])
def delete():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        agree = request.form.get("agree")
        
        if not email or not password:
            flash("Please fill all required fields.")
            return redirect("/delete")
        
        user = db.execute("SELECT * FROM user_profile WHERE email=? AND username=?", email, session["username"])
        if not user:
            flash("Invalid email.")
            return redirect("/delete")
        
        if not check_password_hash(user[0]["password_hash"], password):
            flash("Invalid password.")
            return redirect("/delete")
        
        if not agree:
            flash("Please agree to proceed with the account deletion.")
            return redirect("/delete")
        
        flash("Account deleted.")
        db.execute("DELETE FROM user_profile WHERE email =? AND username=?", email, session["username"])
        session.clear()

        return redirect("/")
    return render_template("delete.html")

@login_required
@app.route("/profile")
def profile():
    user = db.execute("SELECT * FROM user_profile WHERE username=?;", session["username"])
    first_name = user[0]["first_name"]
    middle_name = user[0]["middle_name"]
    last_name = user[0]["last_name"]
    username = user[0]["username"]
    email = user[0]["email"]            
    return render_template("profile.html", first_name=first_name, middle_name=middle_name, last_name=last_name, username=username, email=email)

@login_required
@app.route("/edit", methods=["GET", "POST"])
def edit():
    if request.method == "POST":
        user = db.execute("SELECT * FROM user_profile WHERE username=?;", session["username"])
        old_username = user[0]["username"]

        new_first_name = request.form.get("first_name")
        new_middle_name = request.form.get("middle_name")
        new_last_name = request.form.get("last_name")
        new_username = request.form.get("username")
        new_email = request.form.get("email")
        
        if not new_first_name or not new_last_name or not new_username or not new_email:
            flash("Please fill any empty field.")
            return redirect("/edit")

        db.execute("UPDATE user_profile SET first_name=?, middle_name=?, last_name=?, username=?, email=? WHERE username=?;", new_first_name, new_middle_name, new_last_name, new_username, new_email, old_username)
        session["username"] = new_username

        flash("Profile edited.")
        return redirect("/profile")
    
    user = db.execute("SELECT * FROM user_profile WHERE username=?;", session["username"])
    first_name = user[0]["first_name"]
    middle_name = user[0]["middle_name"]
    last_name = user[0]["last_name"]
    username = user[0]["username"]
    email = user[0]["email"]
    return render_template("/edit.html", first_name=first_name, middle_name=middle_name, last_name=last_name, username=username, email=email)

@login_required
@app.route("/change_password", methods=["POST", "GET"])
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        new_password_confirmation = request.form.get("new_password_confirmation")

        if not current_password or not new_password or not new_password_confirmation:
            flash("Please fill all required fields.")
            return redirect("/change_password")
        
        user = db.execute("SELECT * FROM user_profile WHERE username=?;", session["username"])
        if not check_password_hash(user[0]["password_hash"], current_password):
            flash("Invalid current password.")
            return redirect("/change_password")
        
        if new_password == current_password:
            flash("Please choose a new passowrd that is different from you current password.")
            return redirect("/change_password")
        
        if not is_strong_password(new_password):
            flash("Your new password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one digit, and one special character.")
            return redirect("/change_password")

        if new_password != new_password_confirmation:
            flash("The passwords do not match.")
            return redirect("/change_password")
        
        db.execute("UPDATE user_profile SET password_hash=? WHERE username=?", generate_password_hash(new_password, method="sha256"), session["username"])

        flash("Password has been changed.")
        return redirect("/edit")
    
    return render_template("change_password.html")

@login_required
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    options = ["CASH", "ASSET", "LIABILITY"]
    transactions = ["ADD", "REMOVE"]
    inorout = ["INCOME", "EXPENSE"]
    if request.method == "POST":
        clear = request.form.get("clear")
        if clear:
            agree = request.form.get("agree")
            if not agree:
                flash("Please agree to proceed with clearing equity.")
                return redirect("/dashboard")
            db.execute("DELETE FROM cash WHERE username=?;", session["username"])
            db.execute("DELETE FROM assets WHERE username=?;", session["username"])
            db.execute("DELETE FROM liabilities WHERE username=?;", session["username"])
            flash("Your cash, assets and liabilities have been cleared.")
            return redirect("/dashboard")
    
        option = request.form.get("option")
        action = request.form.get("action")
        amount = request.form.get("amount")
        transaction = request.form.get("transaction")
        name = request.form.get("name").strip().upper()
        description = request.form.get("description").strip().capitalize()

        if not option:
            flash("Please select an option.")
            return redirect("/dashboard")
        
        if not amount:
                flash("Please enter an amount.")
                return redirect("/dashboard")

        try:
            amount = int(amount)
            if amount <= 0:
                flash("Please enter a positive amount.")
                return redirect("/dashboard")
        except ValueError:
            flash("Please enter a number in amount.")
            return redirect("/dashboard")
        
        if option == options[0]:   
            if not action:
                flash("Please select income or expense.")
                return redirect("/dashboard")
         
            if action in inorout:
                db.execute("INSERT INTO cash (username, action, description, amount) VALUES (?, ?, ?, ?);", session["username"], action, description, amount)
                flash(f"{usd(amount)} was added to your cash as an {action}.")
                return redirect("/dashboard")
            
            else: 
                flash("Invalid selection. Please select income/expense")
                return redirect("/dashboard")
        
        if not transaction:
            flash("Please select add/remove.")

        if not name:
            flash("Please input the name for your asset/liability.")
            return redirect("/dashboard")
        
        elif option == options[1]:
            current_asset = db.execute("SELECT * FROM assets WHERE username=? AND name=?;", session["username"], name)
            if transaction == transactions[0]:
                if not current_asset:
                    db.execute("INSERT INTO assets (username, name, description, amount) VALUES (?, ?, ?, ?);", session["username"], name, description, amount)
                    flash(f"{usd(amount)} was added to your assets: {name}.")
                    return redirect("/dashboard")
                
                db.execute("UPDATE assets SET amount=amount+? WHERE username=? AND name=?;", amount, session["username"], name)
                flash(f"{usd(amount)} was added to your asset: {name}.")
                return redirect("/dashboard")

            elif transaction == transactions[1]:
                if not current_asset:
                    flash(f"{name} was not added to be removed.")
                    return redirect("/dashboard")
                
                db.execute("UPDATE assets SET amount=amount+? WHERE username=? AND name=?;", -amount, session["username"], name)
                check_for_zero = db.execute("SELECT * FROM assets WHERE username=? AND name=?;", session["username"], name)
                if check_for_zero[0]["amount"] == 0:
                    db.execute("DELETE FROM assets WHERE username=? AND name=?;", session["username"], name)
                flash(f"{usd(amount)} was removed from your asset: {name}.")
                return redirect("/dashboard")
            
            else: 
                flash("Invalid transaction.")
                return redirect("/dashboard")
            
        elif option == options[2]:
            current_liability = db.execute("SELECT * FROM liabilities WHERE username=? AND name=?;", session["username"], name)
            if transaction == transactions[0]:
                if not current_liability:
                        db.execute("INSERT INTO liabilities (username, name, description, amount) VALUES (?, ?, ?, ?);", session["username"], name, description, amount)
                        flash(f"{usd(amount)} was added to your liabilities: {name}.")
                        return redirect("/dashboard")
                    
                db.execute("UPDATE liabilities SET amount=amount+? WHERE username=? AND name=?;", amount, session["username"], name)
                flash(f"{usd(amount)} was added to your liability: {name}.")
                return redirect("/dashboard")

            elif transaction == transactions[1]:
                if not current_liability:
                    flash(f"{name} was not added to be removed.")
                    return redirect("/dashboard")
                
                db.execute("UPDATE liabilities SET amount=amount+? WHERE username=? AND name=?;", -amount, session["username"], name)
                check_for_zero = db.execute("SELECT * FROM liabilities WHERE username=? AND name=?;", session["username"], name)
                if check_for_zero[0]["amount"] == 0:
                    db.execute("DELETE FROM liabilities WHERE username=? AND name=?;", session["username"], name)
                flash(f"{usd(amount)} was removed from your liability: {name}.")
                return redirect("/dashboard")
            
            else: 
                flash("Invalid transaction.")
                return redirect("/dashboard")
            
        else:
            flash("Invalid option.")
        
        return redirect("/dashboard")

    assets = db.execute("SELECT * FROM assets WHERE username=?;", session["username"])
    if assets:
        total = 0
        for asset in assets:
            total += int(asset["amount"])
        
        current_assets = total
    else:
        current_assets = 0

    liabilities = db.execute("SELECT * FROM liabilities WHERE username=?;", session["username"])
    if liabilities:
        total = 0
        for liability in liabilities:
            total += int(liability["amount"])
        
        current_liabilities = total
    else:
        current_liabilities = 0

    money = db.execute("SELECT * FROM cash WHERE username=?;", session["username"])
    total_incomes = 0
    total_expenses = 0
    if money:
        total = 0
        for cash in money:
            if cash["action"] == inorout[0]:
                total_incomes += cash["amount"]
                total += int(cash["amount"])
            else:
                total_expenses += cash["amount"]
                total -= int(cash["amount"])
        
        current_cash = total
    else:
        current_cash = 0
        total_incomes = 0
        total_expenses = 0

    return render_template("dashboard.html", options=options, transactions=transactions, inorout=inorout, current_cash=current_cash, total_incomes=total_incomes, total_expenses=total_expenses, current_assets=current_assets, current_liabilities=current_liabilities, assets=assets, liabilities=liabilities, money=money, usd=usd)