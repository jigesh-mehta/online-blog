#!/usr/bin/env python

import webapp2
import os
import jinja2
from google.appengine.ext import db
import re
import random
import string
import hashlib
import hmac
import json
import time
from google.appengine.api import memcache
import time
import logging

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

class BaseHandler(webapp2.RequestHandler):

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def top_blogs(self, update = False):
		key = 'front-page'
		front_page = memcache.get(key)
		curr_time = time.time()
		if front_page is None or update:
			blogs = db.GqlQuery("select * from Blog order by created desc limit 10")
			front_page = self.render_str('display-blog.html', blogs = blogs)
			memcache.set(key, front_page)
			memcache.set('accessed-time', time.time())
		return front_page, curr_time

class MainHandler(BaseHandler):
    def get(self):
        self.write('<h1>Hello Udacity!!!!</h1>')


class BlogHandler(BaseHandler):
	def get(self):
		front_page, curr_time = self.top_blogs()
		diff_time = int(curr_time - memcache.get('accessed-time'))
		front_page += '<div>queried %s seconds ago</div>' % diff_time
		self.write(front_page)

class Blog(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

class NewBlogPostHandler(BaseHandler):
	def display_newblog(self, subject="", content="", error=""):
		self.render('newpost-blog.html', subject = subject, content = content, error = error)

	def get(self):
		self.display_newblog()

	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			b = Blog(subject = subject, content = content)
			b.put()
			b_id = b.key().id()
			self.top_blogs(True)
			memcache.set(str(b_id), time.time())
			self.redirect('/blog/'+ str(b_id))
		else:
			error = "Please enter both the values to proceed."
			self.display_newblog(subject, content, error)

class NewBlogHandler(BaseHandler):
	def get(self, blog_id):
		saved_time = memcache.get(str(blog_id))
		queried_time = 0
		if saved_time:
			queried_time = int(time.time() - saved_time)
		else:
			memcache.set(str(blog_id), time.time())
		b = Blog.get_by_id(int(blog_id))
		self.render('blog.html', blog = b, queried_time = queried_time)

class User(db.Model):
	user_id = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def user_exists(username):
	u = User.all().filter('user_id =', username).get()
	return u

def valid_username(username):
	return USER_RE.match(username)

def valid_password(password):
	return PASS_RE.match(password)

def valid_email(email):
	return EMAIL_RE.match(email)

def match_pass(password, verify):
	return password == verify

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return make_pw_hash(name, pw, salt) == h

SECRET = 'imsosecret'
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return '%s|%s' % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')
    if hash_str(str(val[0])) == val[1]:
        return val[0]

class SignupHandler(BaseHandler):

	def display_form(self, uname_err="", password_err="", verify_err="", email_err="", uname="", email=""):
		self.render('signup.html', uname_error = uname_err, password_error = password_err,
		 verify_error = verify_err, email_error = email_err, uname = uname, email = email)

	def get(self):
		self.display_form()

	def post(self):
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		error_flag = False
		uname_err = ''
		password_err = ''
		verify_err = ''
		email_err = ''

		if not valid_username(self.username):
			uname_err = "That's not a valid username."
			error_flag = True
		elif user_exists(self.username):
			uname_err = "Username already taken."
			error_flag = True
		if not valid_password(self.password):
			password_err = "That wasn't a valid password."
			error_flag = True
		elif not match_pass(self.password, self.verify):
			verify_err = "Your passwords didn't match."
			error_flag = True
		if not self.email == '' and not valid_email(self.email):
			email_err = "That's not a valid email."
			error_flag = True

		if error_flag:
			self.display_form(uname_err, password_err, verify_err, email_err, self.username, self.email)
		else:
			u = User(user_id = self.username, password = make_pw_hash(self.username, self.password))
			u.put()
			#pw_hash_val = make_pw_hash(username, password)
			usr_secure = make_secure_val(str(u.key().id()))
			cookie = 'user-id=%s; Path=/' % usr_secure
			self.response.headers.add_header('Set-Cookie', str(cookie))

			self.redirect('/blog/welcome')

class WelcomeHandler(BaseHandler):
	def get(self):
		user_id_cookie = self.request.cookies.get('user-id')
		if user_id_cookie:
			user_id = check_secure_val(user_id_cookie)
			if user_id:
				usr = User.get_by_id(int(user_id))
				if usr:
					self.write("Welcome, %s" % usr.user_id)
				else:
					self.redirect("/blog/signup")
			else:
				self.redirect("/blog/signup")
		else:
			self.redirect("/blog/signup")
			

class JsonBlogHandler(BaseHandler):
	def get(self):
		self.response.headers['Content-Type'] = "application/json; charset=UTF-8"
		list_full_content = []
		blogs = db.GqlQuery("select * from Blog order by created desc limit 10")
		blogs = list(blogs)

		for blog in blogs:
			dict_each_blog = {}
			dict_each_blog["content"] = blog.content
			dict_each_blog["subject"] = blog.subject
			dict_each_blog["created"] = blog.created.strftime('%c')
			dict_each_blog["last_modified"] = blog.last_modified.strftime('%c')
			list_full_content.append(dict_each_blog)

		json_full_content = json.dumps(list_full_content)
		self.write(json_full_content)

class JsonNewBlogHandler(BaseHandler):
	def get(self, blog_id):
		blog = Blog.get_by_id(int(blog_id))
		self.response.headers['Content-Type'] = "application/json; charset=UTF-8"
		dict_each_blog = {}
		dict_each_blog["content"] = blog.content
		dict_each_blog["subject"] = blog.subject
		dict_each_blog["created"] = blog.created.strftime('%c')
		dict_each_blog["last_modified"] = blog.last_modified.strftime('%c')		

		json_full_content = json.dumps(dict_each_blog)
		self.write(json_full_content)

class LoginHandler(BaseHandler):
	def display_login(self, error=""):
		self.render('login.html', error = error)

	def get(self):
		self.display_login()

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		user = User.all().filter('user_id =', username).get()
		if user and valid_pw(username, password, user.password):
			usr_secure = make_secure_val(str(user.key().id()))
			cookie = 'user-id=%s; Path=/' % usr_secure
			self.response.headers.add_header('Set-Cookie', str(cookie))
			self.redirect('/blog/welcome')
		else:
			error = "Invalid login"
			self.display_login(error = error)

class LogoutHandler(BaseHandler):
	def get(self):
		cookie = 'user-id=; Path=/'
		self.response.headers['Set-Cookie'] = cookie
		self.redirect('/blog/signup')

class Flush(BaseHandler):
	def get(self):
		memcache.flush_all()
		self.redirect('/blog')

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/blog', BlogHandler),
    ('/blog/newpost', NewBlogPostHandler),
    ('/blog/(\d+)', NewBlogHandler),
    ('/blog/signup', SignupHandler),
    ('/blog/welcome', WelcomeHandler),
    ('/blog/.json', JsonBlogHandler),
    ('/blog/(\d+).json', JsonNewBlogHandler),
    ('/blog/login', LoginHandler),
    ('/blog/logout', LogoutHandler),
    ('/blog/flush', Flush)
], debug=True)
