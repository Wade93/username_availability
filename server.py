from flask import Flask, render_template, request, redirect, flash, session
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

app = Flask(__name__)
app.secret_key = "super secret"
bcrypt = Bcrypt(app)

@app.route('/')
def registration_or_login():
    if 'fname_entry' not in session:
        session['fname_entry'] = ''
    if 'lname_entry' not in session:
        session['lname_entry'] = ''
    if 'email_entry' not in session:
        session['email_entry'] = ''
    return render_template('index.html')

@app.route('/success')
def successful_login():
    if 'userid' not in session:
        return redirect('/')
    return render_template('success.html')

@app.route("/username", methods=['POST'])
def username():
    length = False
    found = False
    uname_length = list(request.form['username'])
    if len(uname_length) > 3:
        length = True
    mysql = connectToMySQL('reg_n_log')        # connect to the database
    query = "SELECT username from users WHERE users.username = %(user)s;"
    data = { 'user': request.form['username'] }
    result = mysql.query_db(query, data)
    if result:
        found = True
    return render_template('partials/username.html', found=found, length=length)
    # render a partial and return it
    # Notice that we are rendering on a post! Why is it okay to render on a post in this scenario?
    # Consider what would happen if the user clicks refresh. Would the form be resubmitted?

@app.route("/usersearch")
def search():
    print("ENGAGING USERSEARCH")
    found = False
    mysql = connectToMySQL("reg_n_log")
    query = "SELECT * FROM users WHERE first_name LIKE %%(name)s;"
    data = {
        "name" : request.args.get('name') + "%"  # get our data from the query string in the url
    }
    results = mysql.query_db(query, data)
    if results:
        found = True
    print("*"*20)
    print("RESULTS", results)
    return render_template("success.html", users = results, found=found) # render a template which uses the results

@app.route("/search_bar_results")
def search_results():
    print("WE ARE RUNNING SEARCH_BAR_RESULTS")
    found = False
    mysql = connectToMySQL("reg_n_log")
    query = "SELECT * FROM users WHERE first_name LIKE %%(name)s;"
    data = {
        "name" : request.args.get('name') + "%"  # get our data from the query string in the url
    }
    print(query)
    results = mysql.query_db(query, data)
    if results:
        found = True
    print("*"*20)
    print("RESULTS", results)
    return render_template("partials/search_results.html", users = results, found=found) # render a template which uses the results


@app.route('/process', methods=['POST'])
def process():
    is_valid = True		# assume True
    if len(request.form['fname']) < 1:
        is_valid = False
        flash("Please enter a first name.", "fname")
    if len(request.form['fname']) > 0:
        if len(request.form['fname']) < 2:
            is_valid = False
            flash("Please enter a valid first name. ( > 2 Characters!)", "fname_val")
    if len(request.form['lname']) < 1:
        is_valid = False
        flash("Please enter a last name.", "lname")
    if len(request.form['lname']) > 0:
        if len(request.form['lname']) < 2:
            is_valid = False
            flash("Please enter a valid last name. ( > 2 Characters!)", "lname_val")
    if len(request.form['username']) < 1:
            is_valid = False
            flash("Please enter a Username", "uname")
    if len(request.form['username']) > 0:
        if len(request.form['username']) < 4:
            is_valid = False
            flash("Username should be at least 4 characters.", "uname_val")
    if len(request.form['email']) < 1:
        is_valid = False
        flash("Please enter your email.", "email_enter")
    if len(request.form['email']) > 0:
        if not EMAIL_REGEX.match(request.form['email']):
            is_valid = False
            flash("Please enter a valid email address.", "email_val")
    mysql = connectToMySQL("reg_n_log")
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = { "email" : request.form["email"] }
    result = mysql.query_db(query, data)
    if len(result) > 0:
        is_valid = False
        flash("A user with that email already exists.", "user_exists")
    if len(request.form['pw']) < 1:
        is_valid = False
        flash("Please enter a password.", "pw_enter")
    if len(request.form['pw']) > 0:
        if not re.match(r'[A-Za-z0-9]{8,}', request.form['pw']):
            is_valid = False
            flash("Passwords must be a minimum of 8 characters and include at least one Capital(s) and a Number(0-9)", "pw_minimum")
    if len(request.form['pwc']) < 1:
        is_valid = False
        flash("Please confirm your password.", "confirm")
    if len(request.form['pwc']) > 0:
        if request.form['pwc'] != request.form['pw']:
            is_valid = False
            flash("Passwords must match.", "pw_match")
    if not is_valid:
        session['fname_entry'] = request.form['fname']
        session['lname_entry'] = request.form['lname']
        session['username'] = request.form['username']
        session['email_entry'] = request.form['email']
        return redirect('/')
    else:
        pw_hash = bcrypt.generate_password_hash(request.form['pw']) 
        print(pw_hash)  
        mysql = connectToMySQL("reg_n_log")
        query = "INSERT INTO users (first_name, last_name, email, user_pw) VALUES (%(fn)s, %(ln)s, %(email)s, %(password_hash)s);"
        data = {
            "fn": request.form['fname'],
            "ln": request.form['lname'],
            "email": request.form['email'],
            "password_hash": pw_hash
            }
        NewUser = mysql.query_db(query, data)
        mysql = connectToMySQL("reg_n_log")
        query = f"SELECT * FROM users WHERE user_id = {NewUser};"
        result = mysql.query_db(query)
        session['userid'] = result[0]['user_id']
        session['username'] = result[0]['first_name']
        return redirect("/success")


@app.route('/login', methods=['POST'])
def login():
    mysql = connectToMySQL("reg_n_log")
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = { "email" : request.form["email"] }
    result = mysql.query_db(query, data)
    if len(result) > 0:
        if bcrypt.check_password_hash(result[0]['user_pw'],request.form['pw']):
            session['userid'] = result[0]['user_id']
            session['username'] = result[0]['first_name']
            return redirect('/success')
    flash("You could not be logged in")
    return redirect("/")

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)