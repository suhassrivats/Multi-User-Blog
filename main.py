import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2
from google.appengine.ext import db

from user_models import *
from post_models import *

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Validator Functions
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
secret = 'fart'


def valid_username(username):
    """Validate username
    - Example:
        if username:
            return USER_RE.match(username)
        else:
            return username
    """
    return username and USER_RE.match(username)


def valid_password(password):
    """Validate password"""
    return password and PASS_RE.match(password)


def valid_email(email):
    """Validate email"""
    return not email or EMAIL_RE.match(email)


def make_salt(length=5):
    """Generate random letters"""
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    """Generate hashed password"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    """Validate the hash passwords of existing and entered ones.
    - Entered password is in string format, therefore generate a hash value of
    entered password with the same salt value as of existing password.
    - Compare two hashed passwords. Return True if they match. False otherwise.
    """
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def users_key(group='default'):
    return db.Key.from_path('users', group)


class Handler(webapp2.RequestHandler):

    """Defines functions for rendering pages and setting cookies"""

    def write(self, *a, **kw):
        """Writes to the web page"""
        self.response.write(*a, **kw)

    def render_str(self, template, **kw):
        """Renders a Jinja template"""
        kw['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(kw)

    def render(self, template, **kw):
        """Writes rendered template to page"""
        self.write(self.render_str(template, **kw))

    def read_secure_cookie(self, name):
        """Reads a cookie and returns its value"""
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def error(self):
        """Renders error page"""
        self.render('error.html')

    def initialize(self, *a, **kw):
        """Initializes the page with the signed-in user"""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        username = self.read_secure_cookie('user')
        # user is being set/initialized
        self.user = User.gql("WHERE username = '%s'" % username).get()


class Posts(Handler):

    """List all the blogs"""

    def get(self):
        posts = BlogPost.gql("ORDER BY created DESC")
        self.render("front.html", posts=posts)


class SignUp(Handler):

    """Handles all functionalities of user SignUp"""

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username, password=password)

        if not valid_username(username):
            have_error = True
            params['error_username'] = "That's not a valid username."

        if not valid_password(password):
            have_error = True
            params['error_password'] = "That's not a valid password."
        elif password != verify:
            have_error = True
            params['error_verify'] = "Your passwords didn't match."

        if not valid_email(email):
            have_error = True
            params['error_email'] = "That's not a valid email."

        if have_error:
            print "#" * 10
            print(params)
            print "#" * 10
            self.render('signup-form.html', **params)

        else:
            # Everything is good, register the user
            user = User(username=username,
                        pwd_hash=make_pw_hash(username, password),
                        email=email)
            user.put()
            user_cookie = make_secure_val(str(username))
            self.response.headers.add_header(
                "Set-Cookie", "user=%s; Path=/" % user_cookie)
            time.sleep(0.1)
            self.redirect("/")


class Login(Handler):

    """Handles user login"""

    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        user = User.gql("WHERE username = '%s'" % username).get()

        if user and valid_pw(username, password, user.pwd_hash):
            user_cookie = make_secure_val(str(username))
            self.response.headers.add_header(
                "Set-Cookie", "user=%s; Path=/" % user_cookie)
            self.redirect("/")

        else:
            error = "Not a valid username or password"
            self.render("login.html", username=username, error=error)


class Logout(Handler):

    """Handles user logout, redirects to signup on completion"""

    def get(self):
        self.response.headers.add_header("Set-Cookie", "user=; Path=/")
        self.redirect("/login")


class NewPost(Handler):

    """Create a new post"""

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        """Creates a new post and redirects to new post page"""
        if not self.user:
            self.redirect('/')

        user = self.user

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = user

        params = dict()

        if subject and content:
            post = BlogPost(subject=subject, content=content, author=author)
            post.put()
            self.redirect('/post/%s' % str(post.key.id()))

        else:
            params['error'] = "Subject and content cannot be empty"
            self.render('newpost.html', **params)


class ViewPost(Handler):

    """Displays a particular post along with comments and likes"""

    def get(self, post_id):
        key = ndb.Key('BlogPost', int(post_id))
        post = key.get()
        # print(post.key().id())
        self.render('viewpost.html', post=post)


class DeletePost(Handler):

    """Handles deletion of blog posts"""

    def post(self, post_id):
        key = ndb.Key('BlogPost', int(post_id))
        post = key.get()
        if post and post.author.username == self.user.username:
            key.delete()
            time.sleep(0.1)
        self.redirect("/")

    # def post(self, post_id):
    #     key = ndb.Key('BlogPost', int(post_id))
    #     post = key.get()
    #     if post and post.author.username == self.user.username:
    #         key.delete()
    #         time.sleep(0.1)

    #     self.redirect("/")


class EditPost(Handler):

    def get(self, post_id):
        """
            - make sure user is signed in, post exists, user owns post
            - render editpost.html
        """
        key = ndb.Key('BlogPost', int(post_id))
        post = key.get()
        if self.user and post and post.author.username == self.user.username:
            self.render('editpost.html', post=post)
        else:
            self.redirect('/')

    def post(self, post_id):
        """"""
        key = ndb.Key('BlogPost', int(post_id))
        post = key.get()
        # params = dict()
        if self.user and post and post.author.username == self.user.username:
            subject = self.request.get("subject")
            content = self.request.get("content")
            if subject and content:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/post/%s' % str(post.key.id()))
            else:
                error = "Subject and content cannot be empty"
                self.render('editpost.html', error=error)
        else:
            self.redirect('/post/%s' % str(post.key.id()))

# URL routing
app = webapp2.WSGIApplication([('/', Posts),
                               ('/signup', SignUp),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/newpost', NewPost),
                               ('/post/([0-9]+)', ViewPost),
                               ('/post/([0-9]+)/delete', DeletePost),
                               ('/post/([0-9]+)/edit', EditPost),
                               ],
                              debug=True)
