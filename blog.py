import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

#Loads Jinja and sets the directory for the templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'j9jhexfFzAhhN35P6aPI'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#The main handler with convenience functions.
class BlogHandler(webapp2.RequestHandler):
    #writes HTML
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    #Writes with parameters
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    #Uses write() and render_str()
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    #Uses make_secure_val() to put the cookie in the browser
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    #reads the cookie in the browser and determines if it is secure
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    #logs a user in by setting a secure cookie
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    #logs the user out by deleting the cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    #checks to see if a user is logged in every time a page is loaded
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

#renders the subject and content of a post object
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

#redirects to the main page and front.html
class MainPage(BlogHandler):
    def get(self):
        self.redirect("/blog")


#makes a salt for the password
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

#makes a password hash by by adding the salt
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

#checks to see if a password is valid by checking to see if it's hash is
#equal to output of make_pw_hash()
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

#returns the user's key
def users_key(group='default'):
    return db.Key.from_path('users', group)

#the user object, including the name, hash of the password, and email
#along with decorators. Inherits from db.model.
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


#Setting the key for the entire blog
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

#Inherits from db.Model to define data for a post.
#This is used in BlogFront and PostPage.
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now_add=True)
    likes = db.ListProperty(int)
    authorName = db.StringProperty()

    #display the contents of the post
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

        if not post:
            self.error(404)
            return

#Model of a comment which inherits from db.model. parentKey corresponds to
#whichever post the comment is on.
class Comment(db.Model):
    comment = db.TextProperty()
    parentKey = db.IntegerProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now_add=True)
    authorName = db.StringProperty()

    def render(self):
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str("comments.html", c=self)

#Lists all of the posts, uses front.html
class BlogFront(BlogHandler):
    def get(self):
        #display posts and comments
        posts = Post.all().order('-created')
        comments = Comment.all().order('created')
        self.render('front.html', posts=posts, comments=comments)

    #submit commments
    def post(self):
        #get key for post
        parentKey = int(p.key().id())
        comment = self.request.get('comment')
        authorName = str(self.user.name)

        if comment:
            #define c variable as Comment() object with attributes
            c = Comment(parent=blog_key(), comment=comment,
                        authorName=authorName, parentKey=parentKey)
            #store c in the database
            c.put()
            #redirect to PostPage/permalink.html
            self.redirect('/blog/%s' % str(parentKey))
        else:
            error = "comment, please!"
            self.render("permalink.html", comment=comment)

#Lists an individual post, uses permalink.html
class PostPage(BlogHandler):
    def get(self, post_id):
        postKey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(postKey)
        comments = Comment.all().order('created')
        if not post:
            self.error(404)
            return

        self.render("permalink.html", p=post, comments=comments)

    #submit comments
    def post(self, post_id):
        #get key for post
        parentKey = int(post_id)
        comment = self.request.get('comment')
        authorName = str(self.user.name)

        if comment:
            #define c variable as Comment() object with attributes
            c = Comment(parent=blog_key(), comment=comment,
                        authorName=authorName, parentKey=parentKey)
            #store c in the database
            c.put()
            #redirect to PostPage/permalink.html
            self.redirect('/blog/%s' % str(parentKey))
        else:
            error = "comment, please!"
            self.render("permalink.html", comment=comment)

#Retrieves the newpost page, then sends the data for the new post
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            authorName = str(self.user.name)
            likes = []

            if subject and content:
                #define p variable as Post() object with attributes
                p = Post(parent=blog_key(), subject=subject, content=content,
                         authorName=authorName, likes=likes)
                #store p in the database
                p.put()
                #redirect to PostPage/permalink.html
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = "subject and content, please!"
                self.render("newpost.html", subject=subject, content=content, error=error)

#Edit a post
class Edit(BlogHandler):
    def get(self, post_id):
        #if the user is logged in
        if self.user:
            #get the key from the post ID and define it as key
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            #get the post object from the key
            post = db.get(key)
            #if the post doesn't exist
            if not post:
                self.error(404)
                return
            #if the user owns the post
            if post.authorName == str(self.user.name):
                self.render("edit.html", post=post)
            else:
                self.redirect('/blog')
        else:
            self.redirect('/blog')

    def post(self, post_id):
        if self.user:
            subject = self.request.get('subject')
            content = self.request.get('content')
            authorName = str(self.user.name)

            if subject and content:
                #Get the key of the post
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                #if the post exists
                if key:
                    #Define p variable as Post() object with attributes, including the key
                    p = Post(parent=blog_key(), subject=subject, content=content,
                             authorName=authorName, key=key)
                    #if the user owns the post
                    if p.authorName == str(self.user.name):
                        #store p in the database
                        p.put()
                    else:
                        self.redirect('/blog')
                        return
                    #redirect to PostPage/permalink.html
                    self.redirect('/blog/%s' % str(p.key().id()))
                else:
                    self.redirect('/blog')
                    return
            else:
                error = "subject and content, please!"
                self.render("edit.html", subject=subject, content=content, error=error)
        else:
            self.redirect('/blog')
            return

#The following three variables are checked with regular
#expressions before they are used in the Signup handler
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#This is the signup handler. The 'get' function retrieves
#the signup template. Then the 'post' function checks to
#see if the parameters are valid and that the passwords
#match. If everything checks out, it is sent to class Register(Signup).
class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

#Registers a user
class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

#Logs a user in
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)

#Calls the logout function and redirects to the main page
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

#Deletes a post
class Delete(BlogHandler):
    def get(self, post_id):
        #if the user is logged in
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            #if the post exists and the user owns it
            if post and post.authorName == str(self.user.name):
                post.delete()
                self.redirect('/blog')
                return
            else:
                self.redirect('/blog')
                return
        else:
            self.error(404)
            return

#Likes a post
class Like(BlogHandler):
    def get(self, post_id):
        #make sure the user is signed in
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
                #if the post
            if post:
                #check if post.likes already has userID
                #if yes, remove (unlike), if no, add
                if self.user.key().id() in post.likes:
                    post.likes.remove(int(self.user.key().id()))
                else:
                    post.likes.append(int(self.user.key().id()))
                post.put()
                #refresh 'post' to show the like instantly
                post = db.get(key)
                self.redirect('/blog')
                return
            else:
                self.error(404)
                return
        else:
            self.redirect('/blog')
            return

#This part of the webapp2 framework directs the browser to
#a specific page based on which handler is called
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/delete/([0-9]+)', Delete),
                               ('/like/([0-9]+)', Like),
                               ('/edit/([0-9]+)', Edit)], debug=True)
