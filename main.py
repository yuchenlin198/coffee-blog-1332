#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import jinja2
import re
import webapp2
import hmac
import hashlib
import random
import datetime
from string import letters
from datetime import datetime, timedelta

# import code for encoding urls and generating md5 hashes
import urllib, hashlib

from google.appengine.ext import ndb
from google.appengine.api import images

SECRET = 'safe'
default = "http://coffee-blog-1332.appspot.com/static_file/images/logo_blog.png"

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# functions to validate username, password and email

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# encode with hmac with SECRET

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s)) 

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

# get_count like ()
def add_count_like(p):
    add = 1
    add = add + p.like_count
    return add

# get_count comment ()
def add_count_comment(p):
    add = 1
    add = add + p.comment_count
    return add

# prevent attacks of rainbow table

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

# define User table to store user information

class User(ndb.Model):
    username = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty(required = True)
    created_at = ndb.DateTimeProperty(auto_now_add = True)

# Create blog post table to store blog post information

class Blogpost(ndb.Model):
    subject = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created_at = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    author = ndb.StringProperty(required = True)
    author_id = ndb.StringProperty(required = True)
    author_grav = ndb.StringProperty(required = True)
    category = ndb.StringProperty(required = True)
    city = ndb.StringProperty()
    like_count = ndb.IntegerProperty(default = 0) 
    comment_count = ndb.IntegerProperty(default = 0)
    cover_img = ndb.BlobProperty()


# Create a table for comments system.
class Comments(ndb.Model):
    author = ndb.StringProperty(required = True)
    author_id = ndb.StringProperty(required = True)
    author_grav = ndb.StringProperty(required = True) 
    parent_post_id = ndb.StringProperty(required = True)
    is_child_comment = ndb.BooleanProperty (required = False)
    parent_comment_id = ndb.StringProperty(required = False)
    par_comm_author = ndb.StringProperty(required = False)
    par_comm_author_id = ndb.StringProperty(required = False)
    par_author_grav = ndb.StringProperty()
    content = ndb.TextProperty(required = True)
    created_at = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)

# Create a table for like button system.
class Likes(ndb.Model):
    username = ndb.StringProperty(required = True)
    user_id = ndb.StringProperty(required = True) 
    post_id = ndb.StringProperty(required = True)
    likes = ndb.IntegerProperty(default=0)

# Define basic handler

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
        'Set-Cookie',
        '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')

class Image(webapp2.RequestHandler):
    def get(self):
        blogpost_key = ndb.Key(urlsafe=self.request.get('img_id'))
        img = blogpost_key.get()
        if img.cover_img:
            self.response.headers['Content-Type'] = 'image/png'
            self.response.out.write(img.cover_img)
        else:
            self.response.out.write('No image')

# Define signup handler

class SignUpHandler(Handler):
    def get(self):
        self.render("signup_page.html")

    def post (self):
        error_occur = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        if not valid_username(username):
            error_username = "The username you typed in is not valid."
            error_occur = True
        else:
            error_username = ""
            username_check = str(username)
            usersWithName = User.gql("where username = :1", username_check).get()
            if usersWithName:
                error_username = "The username has been registered."
                error_occur = True

        if not valid_password(password):
            error_password = "The password you typed in is not valid."
            error_occur = True
            error_verify = ""
        elif not (password==verify):
            error_verify = "Your passwords did not match."
            error_occur = True
            error_password = ""
        else:
            error_verify = ""
            error_password = ""

        if not (valid_email(email) and email):
            error_email = "The email you typed in is not valid."
            error_occur = True
        else:
            error_email = ""

        if not error_occur:
            self.redirect("/")
            pw_hash = make_pw_hash(username, password)
            a = User(username = username, pw_hash = pw_hash, email=email)
            a.put()
            username = str(username)
            self.set_secure_cookie('username',username)
            self.login(a)
 
        self.render("signup_page.html", username=username, error_username=error_username, 
                    error_password=error_password, error_verify=error_verify, email=email,
                    error_email=error_email)

# Define Login.

class LoginHandler(Handler):
    def get(self):
        self.render("login_page.html")

    def post (self):
        error_occur = False
        username = self.request.get('username')
        password = self.request.get('password')
        username_check = str(username)
        u = User.gql("where username = :1", username_check).get()
        if not u:
            error_username = "The username does not exist."
            error_occur = True
            error_password = ""
        elif not valid_pw(username, password, u.pw_hash): 
            error_password = "The password is incorrect."
            error_occur = True
            error_username = ""
        else:
            self.redirect("/")
            username = str(username)
            self.set_secure_cookie('username',username)
            self.login(u)
        
        if error_occur:
            self.render("login_page.html", username=username, error_username=error_username, 
                        error_password=error_password)

# Define Logout

class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect("/login")

# Blog Code

# blog post front-page
class BlogPostFrontHandler(Handler):
    def render_front(self, subject="", content=""):
        user_id = self.read_secure_cookie('user_id')
        date_a_week_ago = datetime.now() - timedelta(days=7)
        blogpost = Blogpost.query().order(-Blogpost.created_at)
        mostliked = Blogpost.query(Blogpost.created_at > date_a_week_ago)
        mostcomment = Blogpost.query(Blogpost.created_at > date_a_week_ago)
        self.render("frontpage.html", blogpost=blogpost, user_id=user_id, mostliked=mostliked, mostcomment=mostcomment)

    def get(self):
        self.render_front()

    def post(self):
        blogpost = Blogpost.query().order(-Blogpost.created_at)
        mostliked = Blogpost.query().order(-Blogpost.like_count).fetch(limit=2)
        mostcomment = Blogpost.query().order(-Blogpost.comment_count).fetch(limit=2)
        error_occur = False
        user_id = self.read_secure_cookie('user_id')
        username = self.read_secure_cookie('username')
        post_id = self.request.get("post_id")
        b_add = Blogpost.get_by_id(int(post_id))
        post_author = self.request.get("post_author")
        like_before = Likes.gql("where user_id = :user_id AND post_id = :post_id", user_id = user_id, post_id = post_id).get()
        blog_post_created_at = str(self.request.get("blog_post_created_at"))

        if not user_id:
            error_auth = "you need to log in first."
            error_like = ""
            error_occur = True
        else:
            error_auth = ""
            if like_before:
                error_like = "you liked this post already."
                error_occur = True
            elif username == post_author:
                error_like = "you cannot like your own post."
                error_occur = True
            else:
                l = Likes(username=username, user_id=user_id, post_id=post_id, likes=1)
                l.put()
                l.put()
                b_add.like_count = add_count_like(b_add)
                b_add.put()
                b_add.put()

        if error_occur:
            self.render("frontpage.html", blogpost=blogpost, user_id=user_id, mostliked=mostliked, mostcomment=mostcomment, 
                        error_post_id=int(post_id), error_auth=error_auth, error_like=error_like)
        else:
            self.render("frontpage.html", blogpost=blogpost, mostliked=mostliked, mostcomment=mostcomment, user_id=user_id)

class CategoryPostPage(Handler):
    def get(self, categorycity):
        categorycity_str = str(categorycity)
        category_str = categorycity_str.split('/',2)[0]
        city_str = categorycity_str.split('/',2)[1]
        rank_str = categorycity_str.split('/',2)[2]
        blog_cat = Blogpost.query(Blogpost.category == category_str).order(-Blogpost.created_at)
        user_id = self.read_secure_cookie('user_id')

        if not blog_cat:
            self.error(404)
            return

        if city_str == "all":
            if rank_str=="latest" or rank_str=="saves":
                blog_cat = Blogpost.query(Blogpost.category == category_str).order(-Blogpost.created_at)
            elif rank_str=="likes":
                blog_cat = Blogpost.query(Blogpost.category == category_str).order(-Blogpost.like_count)
            elif rank_str=="comments":
                blog_cat = Blogpost.query(Blogpost.category == category_str).order(-Blogpost.comment_count)

            blog_n = blog_cat.count()

            self.render("categorypage.html", blogpost=blog_cat, user_id=user_id, category=category_str, city=city_str, blog_n=blog_n)

        else:
            if rank_str=="latest" or rank_str=="saves":
                blog_cat = Blogpost.query(Blogpost.category == category_str, Blogpost.city == city_str).order(-Blogpost.created_at)
            elif rank_str=="likes":
                blog_cat = Blogpost.query(Blogpost.category == category_str, Blogpost.city == city_str).order(-Blogpost.like_count)
            elif rank_str=="comments":
                blog_cat = Blogpost.query(Blogpost.category == category_str, Blogpost.city == city_str).order(-Blogpost.comment_count)

            blog_n = blog_cat.count()

            self.render("categorypage.html", blogpost=blog_cat, user_id=user_id, category=category_str, city=city_str, blog_n=blog_n)
        

    def post(self, categorycity):
        categorycity_str = str(categorycity)
        category_str = categorycity_str.split('/',2)[0]
        city_str = categorycity_str.split('/',2)[1]
        rank_str = categorycity_str.split('/',2)[2]
        error_occur = False
        user_id = self.read_secure_cookie('user_id')
        username = self.read_secure_cookie('username')
        post_id = self.request.get("post_id")
        b_add = Blogpost.get_by_id(int(post_id))
        post_author = self.request.get("post_author")
        like_before = Likes.gql("where user_id = :user_id AND post_id = :post_id", user_id = user_id, post_id = post_id).get()
        blog_post_created_at = str(self.request.get("blog_post_created_at"))

        if not user_id:
            error_auth = "you need to log in first."
            error_like = ""
            error_occur = True
        else:
            error_auth = ""
            if like_before:
                error_like = "you liked this post already."
                error_occur = True
            elif username == post_author:
                error_like = "you cannot like your own post."
                error_occur = True
            else:
                l = Likes(username=username, user_id=user_id, post_id=post_id, likes=1)
                l.put()
                l.put()
                b_add.like_count = add_count_like(b_add)
                b_add.put()
                b_add.put()

        if city_str == "all":
            if rank_str=="latest" or rank_str=="saves":
                blog_cat = Blogpost.query(Blogpost.category == category_str).order(-Blogpost.created_at)
            elif rank_str=="likes":
                blog_cat = Blogpost.query(Blogpost.category == category_str).order(-Blogpost.like_count)
            elif rank_str=="comments":
                blog_cat = Blogpost.query(Blogpost.category == category_str).order(-Blogpost.comment_count)
        else:
            if rank_str=="latest" or rank_str=="saves":
                blog_cat = Blogpost.query(Blogpost.category == category_str, Blogpost.city == city_str).order(-Blogpost.created_at)
            elif rank_str=="likes":
                blog_cat = Blogpost.query(Blogpost.category == category_str, Blogpost.city == city_str).order(-Blogpost.like_count)
            elif rank_str=="comments":
                blog_cat = Blogpost.query(Blogpost.category == category_str, Blogpost.city == city_str).order(-Blogpost.comment_count)
  
        blog_n = blog_cat.count()
        
        if error_occur:
            self.render("categorypage.html", blogpost=blog_cat, user_id=user_id, rank=rank_str, city=city_str, blog_n=blog_n,
                        error_post_id=int(post_id), error_auth=error_auth, error_like=error_like, category=category_str)
        else:
            self.render("categorypage.html", blogpost=blog_cat, user_id=user_id, category=category_str, rank=rank_str, 
                        city=city_str, blog_n=blog_n)


class AuthorsPostPage(Handler):
    def get(self, author):
        author_str = str(author)
        user_aut = User.query(User.username == author_str).get()
        blog_aut = Blogpost.query(Blogpost.author == author_str).order(-Blogpost.created_at)
        comment_aut = Comments.query(Comments.author == author_str).order(-Comments.created_at)
        size = 40
        l_size = 160
        gravatar_url = "https://www.gravatar.com/avatar/" + hashlib.md5(user_aut.email.lower()).hexdigest() + "?"
        gravatar_url_s = gravatar_url + urllib.urlencode({'d':default, 's':str(size)})
        gravatar_url_l = gravatar_url + urllib.urlencode({'d':default, 's':str(l_size)})
        user_id = self.read_secure_cookie('user_id')

        if not blog_aut:
            self.error(404)
            return

        self.render("authorspage.html", blogpost=blog_aut, user_id=user_id, user_aut=user_aut, comments=comment_aut, 
                   gravatar_url_s=gravatar_url_s, gravatar_url_l=gravatar_url_l)

    def post(self, author):
        author_str = str(author)
        user_aut = User.query(User.username == author_str).get()
        blog_aut = Blogpost.query(Blogpost.author == author_str).order(-Blogpost.created_at)
        comment_aut = Comments.query(Comments.author == author_str).order(-Comments.created_at)
        error_occur = False
        user_id = self.read_secure_cookie('user_id')
        username = self.read_secure_cookie('username')
        post_id = self.request.get("post_id")
        b_add = Blogpost.get_by_id(int(post_id))
        post_author = self.request.get("post_author")
        like_before = Likes.gql("where user_id = :user_id AND post_id = :post_id", user_id = user_id, post_id = post_id).get()
        blog_post_created_at = str(self.request.get("blog_post_created_at"))
        size = 40
        l_size = 160
        gravatar_url = "https://www.gravatar.com/avatar/" + hashlib.md5(user_aut.email.lower()).hexdigest() + "?"
        gravatar_url_s = gravatar_url + urllib.urlencode({'d':default, 's':str(size)})
        gravatar_url_l = gravatar_url + urllib.urlencode({'d':default, 's':str(l_size)})

        if not user_id:
            error_auth = "you need to log in first."
            error_like = ""
            error_occur = True
        else:
            error_auth = ""
            if like_before:
                error_like = "you liked this post already."
                error_occur = True
            elif username == post_author:
                error_like = "you cannot like your own post."
                error_occur = True
            else:
                l = Likes(username=username, user_id=user_id, post_id=post_id, likes=1)
                l.put()
                l.put()
                b_add.like_count = add_count_like(b_add)
                b_add.put()
                b_add.put()

        if error_occur:
            self.render("authorspage.html", blogpost=blog_aut, user_id=user_id, user_aut=user_aut, comments=comment_aut, 
                        gravatar_url_s=gravatar_url_s, gravatar_url_l=gravatar_url_l,
                        error_post_id=int(post_id), error_auth=error_auth, error_like=error_like)
        else:
            self.render("authorspage.html", blogpost=blog_aut, user_id=user_id, author = author_str, comments=comment_aut, 
                        gravatar_url_s=gravatar_url_s, gravatar_url_l=gravatar_url_l)

class CityPostPage(Handler):
    def get(self, cityrank):
        cityrank_str = str(cityrank)
        city_str = cityrank_str.split('/',1)[0]
        rank_str = cityrank_str.split('/',1)[1]
        user_id = self.read_secure_cookie('user_id')

        if rank_str=="latest" or rank_str=="saves":
            blog_city = Blogpost.query(Blogpost.city == city_str).order(-Blogpost.created_at)
        elif rank_str=="likes":
            blog_city = Blogpost.query(Blogpost.city == city_str).order(-Blogpost.like_count)
        elif rank_str=="comments":
            blog_city = Blogpost.query(Blogpost.city == city_str).order(-Blogpost.comment_count)

        blog_n = blog_city.count()   

        self.render("citypostpage.html", blogpost=blog_city, blog_n=blog_n, user_id=user_id, city=city_str)

    def post(self, cityrank):
        cityrank_str = str(cityrank)
        city_str = cityrank_str.split('/',1)[0]
        rank_str = cityrank_str.split('/',1)[1]
        error_occur = False
        user_id = self.read_secure_cookie('user_id')
        username = self.read_secure_cookie('username')
        post_id = self.request.get("post_id")
        b_add = Blogpost.get_by_id(int(post_id))
        post_author = self.request.get("post_author")
        like_before = Likes.gql("where user_id = :user_id AND post_id = :post_id", user_id = user_id, post_id = post_id).get()
        blog_post_created_at = str(self.request.get("blog_post_created_at"))

        if rank_str=="latest" or rank_str=="saves":
            blog_city = Blogpost.query(Blogpost.city == city_str).order(-Blogpost.created_at)
        elif rank_str=="likes":
            blog_city = Blogpost.query(Blogpost.city == city_str).order(-Blogpost.like_count)
        elif rank_str=="comments":
            blog_city = Blogpost.query(Blogpost.city == city_str).order(-Blogpost.comment_count)

        blog_n = blog_city.count()  

        if not user_id:
            error_auth = "you need to log in first."
            error_like = ""
            error_occur = True
        else:
            error_auth = ""
            if like_before:
                error_like = "you liked this post already."
                error_occur = True
            elif username == post_author:
                error_like = "you cannot like your own post."
                error_occur = True
            else:
                l = Likes(username=username, user_id=user_id, post_id=post_id, likes=1)
                l.put()
                l.put()
                b_add.like_count = add_count_like(b_add)
                b_add.put()
                b_add.put()

        if error_occur:
            self.render("citypostpage.html", blogpost=blog_city, user_id=user_id, blog_n=blog_n,
                        error_post_id=int(post_id), error_auth=error_auth, error_like=error_like, city=city_str)
        else:
            self.render("citypostpage.html", blogpost=blog_city, user_id=user_id, city=city_str, blog_n=blog_n)

class PostPage(Handler):
    def get(self, post_id):
        blogpost = Blogpost.get_by_id(int(post_id))
        user_id = self.read_secure_cookie('user_id')
        comments = Comments.query(Comments.parent_post_id == post_id).order(Comments.created_at)

        if not blogpost:
            self.error(404)
            return

        self.render("postpage.html", blogpost=blogpost, comments=comments, user_id=user_id)

    def post(self, post_id):
        error_occur = False
        blogpost = Blogpost.get_by_id(int(post_id))
        comments = Comments.query(Comments.parent_post_id == post_id).order(Comments.created_at)
        user_id = self.read_secure_cookie('user_id')
        username = self.read_secure_cookie('username')
        parent_post_id = post_id
        b_add = Blogpost.get_by_id(int(post_id))
        reply_button = self.request.get("reply_button", None)
        reply_content = self.request.get("reply_content")
        comment_button = self.request.get("comment_button", None)
        comment_content = self.request.get("comment_content")
        parent_comment_id = self.request.get("parent_comment_id")
        par_comm_author = self.request.get("par_comm_author")
        par_comm_author_id = self.request.get("par_comm_author_id")
        like_yes = self.request.get("like_yes")
        post_author = self.request.get("post_author")
        like_before = Likes.gql("where user_id = :user_id AND post_id = :post_id", user_id = user_id, post_id = post_id).get()
        blog_post_created_at = str(self.request.get("blog_post_created_at"))
        
        author_str=str(username)
        comments_aut = User.query(User.username == author_str).get()
        size = 40
        com_gravatar_url = "https://www.gravatar.com/avatar/" + hashlib.md5(comments_aut.email.lower()).hexdigest() + "?"
        com_gravatar_url += urllib.urlencode({'d':default, 's':str(size)})

        error_auth = ""
        error_comment = ""
        error_reply = ""
        error_like = ""

        if not user_id:
            error_auth = "you need to log in to comment."
            error_occur = True
        else:
            if comment_button:
                if not comment_content:
                    error_comment = "Your comments cannot be empty."
                    error_occur = True
                else:
                    c = Comments(author=username, author_id = user_id, parent_post_id = parent_post_id, author_grav=com_gravatar_url,
                                is_child_comment = False, content = comment_content)
                    c.put()
                    c.parent_comment_id = str(c.key.id())
                    c.put()
                    b_add.comment_count = add_count_comment(b_add)
                    b_add.put()
                    b_add.put()

            elif reply_button:
                if not reply_content:
                    error_reply = "Your reply cannot be empty."
                    error_occur = True
                else:
                    par_author_str=str(par_comm_author)
                    par_comm_aut = User.query(User.username == par_author_str).get()
                    par_gravatar_url = "https://www.gravatar.com/avatar/" + hashlib.md5(par_comm_aut.email.lower()).hexdigest() + "?"
                    par_gravatar_url += urllib.urlencode({'d':default, 's':str(size)})
        
                    r = Comments(author=username, author_id = user_id, parent_post_id = parent_post_id,
                                is_child_comment = True, parent_comment_id = parent_comment_id, 
                                par_comm_author = par_comm_author, par_comm_author_id = par_comm_author_id,
                                content = reply_content, author_grav=com_gravatar_url, par_author_grav=par_gravatar_url)
                    r.put()
                    r.put()
                    b_add.comment_count = add_count_comment(b_add)
                    b_add.put()
                    b_add.put()

            elif like_yes:
                if like_before:
                    error_like = "You liked this post already."
                    error_occur = True
                elif username == post_author:
                    error_like = "You cannot like your own post."
                    error_occur = True
                else:
                    l = Likes(username=username, user_id=user_id, post_id=post_id, likes=1)
                    l.put()
                    l.put()
                    b_add.like_count = add_count_like(b_add)
                    b_add.put()
                    b_add.put()

            else:
                raise Exception('no form action given')

        if error_occur:
            self.render("postpage.html", blogpost=blogpost, comments=comments, user_id=user_id, error_comment=error_comment, 
                        error_reply=error_reply, error_auth=error_auth, error_like=error_like)
        else:
            self.render("postpage.html", blogpost=blogpost, comments=comments, user_id=user_id)


class EditPostPage(Handler):
    def get(self, post_id):
        blogpost = Blogpost.get_by_id(int(post_id))
        user_id = self.read_secure_cookie('user_id')

        if not blogpost:
            self.error(404)
        elif not user_id:
            self.redirect("/login")
        elif user_id!=blogpost.author_id:
            self.response.out.write("you have no permisson to edit this post.")
        else:
            self.render("editpost.html", post_id=post_id, subject=blogpost.subject, content=blogpost.content, 
                        category=blogpost.category, city=blogpost.city, user_id=user_id)

    def post(self, post_id):
        subject = self.request.get("subject")
        content = self.request.get("content")
        category = self.request.get("category")
        city = self.request.get("city")
        blogpost = Blogpost.get_by_id(int(post_id))
        cover_img = self.request.get("cover_img")

        if subject and content and category:
            blogpost.subject = subject
            blogpost.content = content
            blogpost.category = category
            blogpost.city = city  

            if cover_img:
                blogpost.cover_img = cover_img

            blogpost.put()
            self.redirect('/%s' % str(blogpost.key.id()))
        else:
            error = "At least one of the fields is empty."
            self.render("editpost.html", post_id=post_id, subject=subject, content=content, user_id=user_id, 
                category=category, error=error)

class EditCommentPage(Handler):
    def get(self, comment_id):
        comments = Comments.get_by_id(int(comment_id))
        user_id = self.read_secure_cookie('user_id')

        if not comments:
            self.error(404)
        elif not user_id:
            self.redirect("/login")
        elif user_id!=comments.author_id:
            self.response.out.write("you have no permisson to edit this post.")
        else:
            self.render("editcomment.html", comment_id=comment_id, comments=comments)

    def post(self, comment_id):
        content = self.request.get("content")
        comments = Comments.get_by_id(int(comment_id))

        if content:
            comments.content = content 
            comments.put()
            comments.put()
            self.redirect('/%s' % str(comments.parent_post_id))
        else:
            error = "Your comment cannot be empty."
            self.render("editcomment.html", comment_id=comment_id, comments=comments, error=error)

class DeletePostPage(Handler):
    def get(self, post_id):
        blogpost = Blogpost.get_by_id(int(post_id))
        user_id = self.read_secure_cookie('user_id')

        if not blogpost:
            self.error(404)
        elif not user_id:
            self.redirect("/login")
        elif user_id!=blogpost.author_id:
            self.response.out.write("you have no permisson to delete this post.")
        else:
            blogpost.key.delete()
            blogpost.key.delete()
            self.redirect("/")

class DeleteCommentPage(Handler):
    def get(self, comment_id):
        comments = Comments.get_by_id(int(comment_id))
        user_id = self.read_secure_cookie('user_id')

        if not comments:
            self.error(404)
        elif not user_id:
            self.redirect("/login")
        elif user_id!=comments.author_id:
            self.response.out.write("you have no permisson to delete this post.")
        else:
            comments.key.delete()
            comments.key.delete()
            self.redirect('/%s' % str(comments.parent_post_id))

class NewPostHandler(Handler):
    def get(self):
        username = self.read_secure_cookie('username')
        user_id = self.read_secure_cookie('user_id')

        if username and user_id:
            self.render("newpost.html", user_id=user_id)
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        username = self.read_secure_cookie('username')
        user_id = self.read_secure_cookie('user_id')
        category = self.request.get("category")
        cover_img = self.request.get("cover_img")
        city = self.request.get("city")
        author_str=str(username)
        user_aut = User.query(User.username == author_str).get()
        size = 40
        gravatar_url = "https://www.gravatar.com/avatar/" + hashlib.md5(user_aut.email.lower()).hexdigest() + "?"
        gravatar_url += urllib.urlencode({'d':default, 's':str(size)})

        if subject and content and category and city and cover_img:
            a = Blogpost(subject = subject, content = content, author = username, author_id = user_id, cover_img=cover_img, 
                         author_grav = gravatar_url, category = category, city = city)
            a.put()
            self.redirect('/%s' % str(a.key.id()))
        elif subject and content and category and city:
            a = Blogpost(subject = subject, content = content, author = username, author_id = user_id, 
                         author_grav = gravatar_url, category = category, city = city)
            a.put()
            self.redirect('/%s' % str(a.key.id()))
        else:
            error = "At least one of the fields is empty."
            self.render("newpost.html", subject=subject, content=content, category=category,
                        city=city, user_id=user_id, error=error)

app = webapp2.WSGIApplication([('/', BlogPostFrontHandler),
                               ('/newpost', NewPostHandler),
                               ('/img', Image),
                               ('/([0-9]+)', PostPage),
                               ('/category/([a-zA-Z0-9]+/[a-zA-Z0-9]+/[a-zA-Z0-9]+)', CategoryPostPage),
                               ('/authors/([a-zA-Z0-9]+)', AuthorsPostPage),
                               ('/city/([a-zA-Z0-9]+/[a-zA-Z0-9]+)', CityPostPage),
                               ('/edit/([0-9]+)', EditPostPage),
                               ('/delete/([0-9]+)', DeletePostPage),
                               ('/editcomment/([0-9]+)', EditCommentPage),
                               ('/deletecomment/([0-9]+)', DeleteCommentPage),
                               ('/signup', SignUpHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler)], debug=True)