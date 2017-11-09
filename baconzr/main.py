import os
import re
import random
import hashlib
import hmac
import logging
import json
import time
from random import randint
from datetime import datetime, timedelta
from string import letters

import webapp2
import jinja2

from google.appengine.api import memcache
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'Templates') #create dir to store jinja2 templates
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True) #autoescape for security

secret = 'shhsupersecret' #hash code
  
def render_str(template, **params): #for jinja2
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val): #used to check password hash
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler): #Main handler, almost every page inherits from this
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d): #render pages in json
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val): #used for logging in
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

    
##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model): 
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff
def age_set(key, val):
	save_time = datetime.utcnow()
	memcache.set(key, (val, save_time))
	
def age_get(key):
	r = memcache.get(key) #memcache
	if r:
		val, save_time = r
		age = (datetime.utcnow() - save_time).total_seconds()
	else:
		val, age = None, 0
	return val, age

def add_post(post):
	post.put()
	time.sleep(0.5)
	get_posts(update = True)
	return str(post.key().id())

def get_posts(update = False):
	q = Post.all().order('-created').fetch(limit = 10)
	mc_key = 'BLOGS'

	posts, age = age_get(mc_key)
	if update or posts is None:
		posts = list(q)
		age_set(mc_key, posts)
	return posts, age
	
def age_str(age):
	s = 'queried %s seconds ago'
	age = int(age)
	if age == 1:
		s = s.replace('seconds','second')
	return s % age
	
	
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	number = db.StringProperty()
	submitter_id = db.StringProperty()
	
	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)

	def as_dict(self):
		time_fmt = '%c'
		d = {'subject': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
		return d
        
class Comment(db.Model):
	parent_post = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	submitter_id = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	
	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("comment.html", p = self)
	
class BlogFront(BlogHandler):
    def get(self):
		if not self.user:
			self.redirect('/signup')
		posts, age = get_posts()
		if self.format == 'html':
			self.render('frontblog.html', posts = posts, age = age_str(age))
		else:
			return self.render_json([p.as_dict() for p in posts])

def get_comments(post_id):
	q = db.GqlQuery("SELECT * FROM Comment WHERE parent_post = :url ORDER BY created ASC", url = post_id)
	return q
	
class PostPage(BlogHandler):
	def get(self, post_id):
		if not self.user:
			self.redirect('/signup')
		post_key = 'POST_' + post_id
		post, age = age_get(post_key)
		comments = get_comments(post_id)
		if not post:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			age_set(post_key, post)
			age = 0
	
		if not post:
			self.error(404)
			return
			
		if self.format == 'html':
			self.render("permalink.html", p = post, age = age_str(age), comments = comments)
		else:
			self.render_json(post.as_dict())

	def post(self, post_id):
		content = self.request.get('content')
		submitter_id = self.request.get('submitter_id')
		
		if content and self.user:
			p = Comment(parent_post = post_id, content = content, submitter_id = self.user.name)
			p.put()
			time.sleep(0.5)
			self.redirect('/%s' % str(post_id))
		else:
			error = "need content!"
			self.render("permalink.html", error=error)
		
		
			
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
			p = Post(parent = blog_key(), subject = subject, content = content, submitter_id = self.user.name)
			p.put()
			time.sleep(0.5)
			p.number = '/%s' % str(p.key().id())
			add_post(p)
			self.redirect('/')
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$") #regex to check for valid names
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$") #regex for valid pass
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$') #regex for valid email
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

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

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class FlushHandler(BlogHandler):
	def get(self):
		memcache.flush_all()
		self.redirect("/")

class NoneHandler(BlogHandler):
	def get(self):
		self.redirect("/")

def Page_key(name = 'default'):
    return db.Key.from_path('Pages', name)


class Page(db.Model):
    url = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    note = db.StringProperty()


class EditPage(BlogHandler):
    def get(self, page_name="code"):
        if self.user:
            self.render("edit.html")
        else:
            self.redirect("/login")
    
    def post(self):
        if not self.user:
            self.redirect('/signup')
            
        content = self.request.get('content')
        note = self.request.get('note')
		 
        if content:
            p = Page(parent = Page_key(), url = "code", content = content, note = note)
            p.put() #put that in the database
            time.sleep(0.5)
            self.redirect('/code')
        else:
            error = "content, please!"
            self.render("edit.html", content=content, error=error)


class WikiPage(BlogHandler):
    def get(self, page_name="code"):
    	if not self.user:
		self.redirect('/signup')
        ver = self.request.get("v")
        
        if ver:
            key = db.Key.from_path('Page', int(ver), parent=Page_key())
            page = db.get(key)
        else:
	#GQL query to display top pages	
            page = db.GqlQuery("SELECT * FROM Page WHERE url = :url ORDER BY created DESC LIMIT 1", url = page_name).get()
        
        if page:
            self.render('page.html', content = page.content, url = page_name)
        
        if not page and self.user:
            self.redirect('/code_edit/')
        
        if not page and not self.user:
            self.redirect('/login')


class HistoryPage(BlogHandler):
    def get(self, page_name="code"):
    	if not self.user:
			self.redirect('/signup')
        pages = Page.all().filter("url =", page_name).order("-created")
        
        if pages:
            self.render('page_history.html', pages = pages)
        
        if not pages and self.user:
            self.redirect('/code_edit/')
        
        if not pages and not self.user:
            self.redirect('/login')



#Based on page, show handler
app = webapp2.WSGIApplication([('/?(?:.json)?', BlogFront),
                               ('/([0-9]+)(?:.json)?', PostPage),
                               ('/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/code', WikiPage),
                               ('/code_edit/', EditPage),
                               ('/code_history/', HistoryPage),
                               ('/code_history/code', WikiPage),
                               ('/welcome', Welcome),
                               ('/flush', FlushHandler),
                               ('/None', NoneHandler)
                               ],
                              debug=True)
