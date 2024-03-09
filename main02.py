from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import Flask, render_template, request, url_for, redirect, logging, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pymysql
import base64

pymysql.install_as_MySQLdb()

app = Flask(__name__)
login_manager = LoginManager(app)
# SQLITE Database
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///contactappdb.db'
# ALLOWED_HOSTS = ['.ap-southeast-2.elasticbeanstalk.com', 'localhost']
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/contactappdb'  # added the users database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = "secret_key"

db = SQLAlchemy(app)  # initialise the database


class User(db.Model, UserMixin):  # creating model
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False, unique=True)
    f_name = db.Column(db.String(200), nullable=False)
    l_name = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    contacts = db.relationship('Contact', backref='user')  # foreign key relationship initialized

    def __repr__(self):  # creating a string
        return '<name %r>' % self.id


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    data = db.Column(db.LargeBinary)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200))
    phone = db.Column(db.BigInteger)
    notes = db.Column(db.String(300))
    category = db.Column(db.Text)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # foreign key of user.id made

    def __repr__(self):  # creating a string
        return '<name %r>' % self.id

    def base64(self):
        return base64.b64encode(self.data).decode("utf-8")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # uses the user id to load users


@app.route('/')
def mainP():
    if current_user.is_authenticated:  # checks if user is logged in (did not log out since last time)
        return redirect(url_for('view'))
    return redirect(url_for('login'))  # delete cache or log out before closing window to go straight to login


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        # hash the user-supplied password and compare it to the hashed password in the database
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))  # if the user doesn't exist or password is wrong, reload the page

        login_user(user, remember=True)  # logs in user and remembers who they are so that they can pass login_required
        return redirect(url_for('view'))
    return render_template('login.html')


@app.route('/signup', methods=["POST", "GET"])
def registerForm():
    if request.method == "POST":
        user_email = request.form.get("email")
        user_f_name = request.form.get("first_name")
        user_l_name = request.form.get("last_name")
        user_password = request.form.get("password")
        hash_pw = generate_password_hash(user_password, method='sha256')  # hash the password for protection
        new_user = User(email=user_email, f_name=user_f_name, l_name=user_l_name, password=hash_pw)  # creating new user
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    else:
        users = User.query.order_by(User.date_added)
        return render_template('signup.html', user=users)


@app.route('/adduser', methods=["POST", "GET"])
@login_required
def adduser():
    if request.method == "POST":
        file = request.files["file"]
        name = request.form.get("name")
        email = request.form.get("email")
        telephone = request.form.get("telephone")
        note = request.form.get("note")
        category = request.form.get("category")
        user_id = current_user.id  # the current user's id is set to be committed to Contact table
        new_contact = Contact(filename=file.filename, data=file.read(), name=name, email=email, phone=telephone, notes=note, category=category, user_id=user_id)
        db.session.add(new_contact)
        db.session.commit()
        return redirect('/view')

    else:
        contacts = Contact.query.order_by(Contact.date_added)
        return render_template('adduser.html', contact=contacts)


@app.route('/logout')
@login_required
def logout():
    logout_user()  # logs out the current user and sends them to login
    return redirect(url_for('login'))


@app.route('/view', methods=["GET"])
@login_required
def view():
    contacts = Contact.query.order_by(Contact.date_added).filter(Contact.user_id == current_user.id).all()
    # filtering through the user_id foreign keys of contacts so only the correct user's contacts are displayed

    return render_template('view.html', contact=contacts)


@app.route('/view_family', methods=["GET"])
@login_required
def view_family():
    contacts = Contact.query.order_by(Contact.date_added).filter(Contact.user_id == current_user.id, Contact.category == "Family").all()
    # filtering through the user_id foreign keys of contacts so only the correct user's contacts are displayed and
    # only the contacts with "Family" as their category
    return render_template('view.html', contact=contacts)


@app.route('/view_friend', methods=["GET"])
@login_required
def view_friend():
    contacts = Contact.query.order_by(Contact.date_added).filter(Contact.user_id == current_user.id, Contact.category == "Friend").all()
    # filtering through the user_id foreign keys of contacts so only the correct user's contacts are displayed and
    # only the contacts with "Friend" as their category
    return render_template('view.html', contact=contacts)


@app.route('/view_work', methods=["GET"])
@login_required
def view_work():
    contacts = Contact.query.order_by(Contact.date_added).filter(Contact.user_id == current_user.id, Contact.category == "Work").all()
    # filtering through the user_id foreign keys of contacts so only the correct user's contacts are displayed and
    # only the contacts with "Work" as their category
    return render_template('view.html', contact=contacts)


@app.route('/search', methods=["GET", "POST"])
@login_required
def search():
    if request.method == "POST":
        search = request.form.get("search")  # fetches the search form user inputted text
        contacts = Contact.query.order_by(Contact.date_added).filter(Contact.user_id == current_user.id, Contact.name.like("%"+search+"%")).all()
    # filtering through the user_id foreign keys of contacts so only the correct user's contacts are displayed The
    # contact with the matching text as the search are selected Using ".like" the code can now show similar results,
    # with values now being allowed before or after the match text. Allowing for first name or last name only searches
    return render_template('view.html', contact=contacts)


@app.route("/delete/<int:id>")
@login_required
def delete(id):
    contact_to_delete = Contact.query.get_or_404(id)  # the id of Contact is used to identify which to delete
    db.session.delete(contact_to_delete)  # information of user id to delete sent
    db.session.commit()
    return redirect('/view')


@app.route("/update/<int:id>", methods=["POST", "GET"])
@login_required
def update(id):
    contact_to_update = Contact.query.get_or_404(id)  # the id of Contact is used to identify which to update
    if request.method == 'POST':
        contact_to_update.filename = request.files["file"]
        contact_to_update.data = contact_to_update.filename.read()
        contact_to_update.name = request.form['name']
        contact_to_update.email = request.form['email']
        contact_to_update.phone = request.form['telephone']
        contact_to_update.notes = request.form['note']
        contact_to_update.category = request.form['category']
        db.session.commit()
        return redirect('/view')
    else:
        return render_template('update.html', contact_to_update=contact_to_update)


if __name__ == "__main__":
    app.run(debug=True)
