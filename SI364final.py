# SI 364 W18 Final Project
# Frankie Antenucci

# Import statements
import os
import requests
import json
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from werkzeug.security import generate_password_hash, check_password_hash
from nyt_movie_reviews_api import api_key  # to get API key

# Imports for login management
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Application configurations
app = Flask(__name__)
app.debug = True
app.use_reloader = True
app.config['SECRET_KEY'] = 'hardtoguessstring'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URL') or "postgresql://localhost/fantenuc364final"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['HEROKU_ON'] = os.environ.get('HEROKU')

# App addition setups
manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

# Login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app) # set up login manager


####################################
######## Association Tables ########
####################################

# Association table between movie reviews
user_movie_collection = db.Table('user_movie_collection', db.Column('user_id', db.Integer, db.ForeignKey('reviews.id')), db.Column('collection_id', db.Integer, db.ForeignKey('userMovieCollections.id')))

search_reviews = db.Table('search_reviews', db.Column('search_id', db.Integer, db.ForeignKey('search.id')), db.Column('review_id', db.Integer, db.ForeignKey('reviews.id')))

##################
##### MODELS #####
##################

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    collection = db.relationship('UserMovieCollection', backref='User') # one-to-many relationship for users and movie collections

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

## DB load function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) # returns User object or None

class SearchTerm(db.Model):
    __tablename__ = 'search'
    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(64), unique=True)
    reviews = db.relationship('Review', secondary=search_reviews, backref=db.backref('search', lazy='dynamic'), lazy='dynamic')

    def __repr__(self):
        return "Term Searched: {}".format(self.term)

class Review(db.Model):
    __tablename__ = 'reviews'
    id = db.Column(db.Integer, primary_key=True)
    movie_title = db.Column(db.String(64)) # display_title from json
    rating = db.Column(db.String(10)) # mpaa_rating from json
    # critic = db.Column(db.String(64)) # by_line from json
    review_title = db.Column(db.String(1000)) # headline from json
    review_summary = db.Column(db.String(1000)) # summary_short from json
    release_date = db.Column(db.String(64)) # opening_date from json

    def __repr__(self):
        return "Movie: {} Rating: {} Release Date: {}".format(self.movie_title, self.rating, self.release_date)

class UserMovieCollection(db.Model):
    __tablename__ = 'userMovieCollections'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    description = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id')) # one-to-many relationship with the Users model (one user, many review collections)
    movies = db.relationship('Review', secondary=user_movie_collection, backref=db.backref('userMovieCollections', lazy='dynamic'), lazy='dynamic') # many-to-many relationship with the Review model (one review might be in many user review collections, one user review collection could have many reviews in it)


########################
######## Forms #########
########################
class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
    username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class ReviewSearchForm(FlaskForm):
    search = StringField('Enter a term to search movie reviews (do not include symbols): ', validators=[Required()])

    def validate_search(self, field):
        symbols = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '?', '<', '>', '~']
        for chr in field.data:
            if chr in symbols:
                raise ValidationError('Search term includes symbols -- refrain from using symbols in search!')

    submit = SubmitField('Submit')

class CreateCollectionForm(FlaskForm):
    name = StringField('Collection Name: ', validators=[Required()])
    movie_picks = SelectMultipleField('Select movies to include: ')
    description = StringField('Enter a brief description on this collection: ', validators=[Required()])
    submit = SubmitField('Create Movie Collection')

class CommentForm(FlaskForm):
    comment = StringField('Please comment on how useful this movies review application was to you: ', validators=[Required(Length(1,250))])
    useful = StringField('Would you use this application again? ', validators=[Required()])
    submit = SubmitField('Submit')

class UpdateButtonForm(FlaskForm):
    submit = SubmitField('Update Description')

class UpdateDescriptionForm(FlaskForm):
    new_description = StringField('What is the new description of the movie collection? (more than one word)', validators=[Required()])

    def validate_new_description(self, field):
        if len(field.data.split()) < 2:
            raise ValidationError('Please enter a description that is more than 2 words')

    submit = SubmitField('Update')

class DeleteButtonForm(FlaskForm):
    submit = SubmitField("Delete Collection")


########################
### Helper functions ###
########################
def get_review_from_api(search_term):
    baseurl = 'https://api.nytimes.com/svc/movies/v2/reviews/search.json?'
    params = {'api_key': api_key, 'query': search_term}
    resp = requests.get(baseurl, params)
    review_list = json.loads(resp.text)['results']
    return review_list

def get_review_by_id(id):
    r = Review.query.filter_by(id=id).first()
    return r

def get_or_create_review(movie_title, rating, review_title, review_summary, release_date):
    r = Review.query.filter_by(review_title=review_title).first()
    if not r:
        r = Review(movie_title=movie_title, rating=rating, review_title=review_title, review_summary=review_summary, release_date=release_date)
        db.session.add(r)
        db.session.commit()
        return r

def get_or_create_search_term(term):
    search_term = SearchTerm.query.filter_by(term=term).first()
    if not search_term:
        search_term  = SearchTerm(term=term)
        review_search = get_review_from_api(term)
        for review in review_search:
            movie_title = review['display_title']
            rating = review['mpaa_rating']
            review_title = review['headline']
            review_summary = review['summary_short']
            release_date = review['opening_date']
            review_obj = get_or_create_review(movie_title, rating, review_title, review_summary, release_date)
            search_term.reviews.append(review_obj)
        db.session.add(search_term)
        db.session.commit()
        return search_term

def get_or_create_collection(name, description, current_user, movie_list=[]):
    collection = UserMovieCollection.query.filter_by(name=name, user_id=current_user.id).first()
    if not collection:
        collection = UserMovieCollection(name=name, user_id=current_user.id, description=description, movies=movie_list)
        for movie in movie_list:
            collection.movies.append(movie)
        db.session.add(collection)
        db.session.commit()
        return collection


########################
#### View functions ####
########################

## Error handling routes
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('base'))
        flash('Invalid username or password.')
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out of the Movies Review Application. Thank you for choosing our app!')
    return redirect(url_for('base'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in to Movie Reviews Application!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

@app.route('/secret')
@login_required
def secret():
    return "Only authenticated users can do this! To do this, please log in to the Movie Reviews Application."

@app.route('/', methods=['GET', 'POST'])
def base():
    form = ReviewSearchForm()
    if form.validate_on_submit():
        get_or_create_search_term(form.search.data)
        return redirect(url_for('review_results', search_term=form.search.data))
    errors = [v for v in form.errors.values()]
    if len(errors) > 0:
        flash("!!!! ERRORS IN FORM SUBMISSION - " + str(errors))
    return render_template('base.html', form=form)

@app.route('/reviews_searched/<search_term>')
def review_results(search_term):
    term = SearchTerm.query.filter_by(term=search_term).first()
    reviews_from_search = term.reviews.all()
    return render_template('searched_reviews.html', reviews=reviews_from_search, term=term)

@app.route('/search_terms')
def search_terms():
    all_terms = SearchTerm.query.all()
    return render_template('search_terms.html', all_terms=all_terms)

@app.route('/all_reviews')
def all_reviews():
    reviews = Review.query.all()
    return render_template('all_reviews.html', all_reviews=reviews)

@app.route('/create_movie_collection',methods=["GET","POST"])
@login_required
def create_user_collection():
    form = CreateCollectionForm()
    reviews = Review.query.all()
    choices = [(r.id, r.movie_title) for r in reviews]
    form.movie_picks.choices = choices
    if request.method == 'POST':
        reviews_selected = form.movie_picks.data
        review_obj = [get_review_by_id(int(id)) for id in reviews_selected]
        get_or_create_collection(name=form.name.data, current_user=current_user, description=form.description.data, movie_list=review_obj)
        return redirect(url_for('user_collections'))
    return render_template('create_user_collection.html', form=form)

@app.route('/collections', methods=["GET","POST"])
@login_required
def user_collections():
    form = UpdateButtonForm()
    form1 = DeleteButtonForm()
    collections = UserMovieCollection.query.filter_by(user_id=current_user.id).all()
    return render_template('user_collections.html', collections=collections, form=form, form1=form1)

@app.route('/collection/<id_num>')
def single_collection(id_num):
    id_num = int(id_num)
    collection = UserMovieCollection.query.filter_by(id=id_num).first()
    movies = collection.movies.all()
    return render_template('single_collection.html', collection=collection, movies=movies)

@app.route('/update/<collection>',methods=["GET","POST"])
def update(collection):
    form = UpdateDescriptionForm()
    if form.validate_on_submit():
        if request.method == 'POST':
            description = form.new_description.data
            c = UserMovieCollection.query.filter_by(description=collection).first()
            c.description = description
            db.session.commit()
            flash('**Updated description of movie collection: {}**'.format(c.name))
            return redirect(url_for('user_collections'))
    errors = [v for v in form.errors.values()]
    if len(errors) > 0:
        flash("!!!! ERRORS IN FORM SUBMISSION - " + str(errors))
    return render_template('update_collection.html', collection=collection, form=form)

@app.route('/delete/<collection>',methods=["GET","POST"])
def delete(collection):
    collection = UserMovieCollection.query.filter_by(name=collection).first()
    db.session.delete(collection)
    db.session.commit()
    flash('**Deleted movie collection: {}**'.format(collection.name))
    return redirect(url_for('user_collections'))

@app.route('/comments')
def comments():
    form = CommentForm()
    return render_template('leave_comments.html', form=form)

@app.route('/view_comments', methods=['GET', 'POST'])
def view_comments():
    form = CommentForm()
    if request.args:
        comment = request.args.get('comment')
        useful = request.args.get('useful')
        return render_template('comments.html', comment=comment, useful=useful)
    return redirect(url_for('comments'))



if __name__ == '__main__':
    db.create_all()
    manager.run()
