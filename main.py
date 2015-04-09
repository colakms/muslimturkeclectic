__author__='ColakMS'

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
import hashlib
import hmac
import os
import random
from string import letters, digits
import urllib2
import json
import webapp2
import jinja2
from time import sleep
from google.appengine.ext import ndb
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

secret = '2S5FX7ZSdRgP'
file_path="mainpage.html"

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class UnapprovedBlog(ndb.Model):
    title = ndb.StringProperty(required = False, indexed = True)
    blog = ndb.TextProperty(required = True)
    url = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    category = ndb.StringProperty(required=True, choices=set(["Algorithm", "Reflection", "Poem"]))
    author = ndb.StringProperty(required=True)

    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.title,
             'content': self.blog,
             'category': self.category,
             'author': self.author,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d

class Blog(ndb.Model):
    title = ndb.StringProperty(required = False, indexed = True)
    blog = ndb.TextProperty(required = True)
    url = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    category = ndb.StringProperty(required=True, choices=set(["Algorithm", "Reflection", "Poem"]))
    author = ndb.StringProperty(required=True)

    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.title,
             'content': self.blog,
             'category': self.category,
             'author': self.author,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d

class Comment(ndb.Model):
    author = ndb.StringProperty(required = True)
    comment = ndb.TextProperty(required = True)
    post_title = ndb.StringProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)

    def as_dict(self):
        time_fmt = '%c'
        d = {'author' : self.author,
             'comment' : self.comment,
             'post_title' : self.post_title,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d

class ApprovedComment(ndb.Model):
    author = ndb.StringProperty(required = True)
    comment = ndb.TextProperty(required = True)
    post_title = ndb.StringProperty(required = True)
    created = ndb.DateTimeProperty(required = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)

    def as_dict(self):
        time_fmt = '%c'
        d = {'author' : self.author,
             'comment' : self.comment,
             'post_title' : self.post_title,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

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

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

class MainPage(Handler):
    def permalink_generator(self):
        posts = ndb.gql("SELECT * FROM Blog ORDER BY created DESC")
        list = posts.fetch(limit=5)

        permalinks = []
        titles = []
        permalink_list = ''

        for l in list:
            permalink = "/subject?subject=" + l.url
            titles.append(l.title)
            permalinks.append(permalink)

        for ctr in range(len(permalinks)):
            permalink_list += '<li><a href=\"' + permalinks[ctr] + '">' + titles[ctr] + '</a></li>'

        return permalink_list

    def render_front(self, file_path, post_notification=False, posts=None, comment_notification=False, comments=None, fullname="", comment_content="", post_title="", id=None, title="", blog="", url="", created=None, category="", author="", error_message="", username="", login_error="", showcase=None, referer="", login_notification=False, update_notification=False):
        permalink_list = self.permalink_generator()

        if showcase:
            self.render(file_path, fullname=fullname, comments=comments, post_title=post_title, showcase=showcase, permalink_list=permalink_list)
        elif login_notification or update_notification:
            self.render(file_path, id=id, title=title, blog=blog, url=url, category=category, author=author, error_message=error_message,
                        permalink_list=permalink_list, referer=referer, login_notification=login_notification, username=username,
                        login_error=login_error, update_notification=update_notification)
        elif post_notification:
            self.render(file_path, post_notification=post_notification, posts=posts, permalink_list=permalink_list)
        elif comment_notification:
            self.render(file_path, comment_notification=comment_notification, comments=comments, permalink_list=permalink_list)
        else:
            posts = ndb.gql("SELECT * FROM Blog ORDER BY created DESC")
            showcases = []
            posts = posts.fetch(limit=2)
            for post in posts:
                showcases += [post]
            self.render(file_path, showcases=showcases, permalink_list=permalink_list)

    def get(self):
        self.render_front(file_path)

class SubjectHandler(MainPage, Blog):
    def get(self):
        uri = self.request.get('subject')
        if uri[-4:] == 'json':
            uri = uri[:-5]
            title = urllib2.unquote(uri)
            blog = ndb.gql("SELECT * FROM Blog WHERE title=:1", title)
            blog = blog.get()
            comments = ndb.gql("SELECT * FROM ApprovedComment WHERE post_title=:ttl ORDER BY created ASC", ttl=title)
            comment_dict = {}
            if comments.count() > 0:
                comments = comments.iter()
                i = 1
                for comment in comments:
                    comment_dict["comment" + str(i)] = comment.as_dict()
                    i += 1
                self.render_json({"blog": blog.as_dict(), "comments": comment_dict})
            else:
                self.render_json({"blog": blog.as_dict()})
        else:
            title = urllib2.unquote(uri)
            post = ndb.gql("SELECT * FROM Blog WHERE title=:1", title)
            showcase = post.get()
            comments = ndb.gql("SELECT * FROM ApprovedComment WHERE post_title=:ttl ORDER BY created ASC", ttl=title)
            comments = comments.iter()
            if self.format == 'html':
                if showcase:
                    self.render_front(file_path, comments=comments, showcase=showcase)
                else:
                    self.error(404)
                    self.render('404.html')
            else:
                if showcase:
                    self.render_json(showcase.as_dict())
                else:
                    self.error(404)
                    self.render('404.html')

    def post(self):
        update_notification = True
        if self.user:
            id = self.request.get("id")
            title = self.request.get("title")
            blog = self.request.get("content")
            category = self.request.get("category")
            author = self.request.get("author")
            id = int(id)
            if not (category and author):
                showcase = Blog.get_by_id(id)
                self.render_front(file_path, id=id, title=showcase.title,
                                  blog=showcase.blog, url=showcase.url, category=showcase.category,
                                  author=showcase.author, update_notification=update_notification)
            else:
                url = urllib2.quote(title)
                if id and title and blog and category and author:
                    p = Blog.get_by_id(id)
                    p.title = title
                    p.blog = blog
                    p.category = category
                    p.author = author
                    p.url = url

                    p.put()

                    new_blog_page = "/subject?subject=" + urllib2.quote(title)
                    sleep(0.3)
                    self.redirect(new_blog_page)
                else:
                    error_message = "You have enter a title and a blog!"
                    self.render_front(file_path, id=id, title=title,
                                  blog=blog, url=url, category=category,
                                  author=author, error_message=error_message, update_notification=update_notification)
        else:
            subject = self.request.get('subject')
            uri = '/login?referer=/subject?subject=' + urllib2.quote(subject)
            #self.response.out.write(uri)
            self.redirect(uri)

class PostHandler(MainPage):
    post_notification = True
    def get(self):
        if self.user:
            raw_posts = ndb.gql("SELECT * FROM UnapprovedBlog ORDER BY created DESC")
            posts = raw_posts.iter()
            self.render_front(file_path, post_notification=self.post_notification, posts=posts)
        else:
            uri = "/login?referer=/post"
            self.redirect(uri)

class CommentHandler(MainPage):
    def get(self):
        if self.user:
            comment_notification = True
            raw_comments = ndb.gql("SELECT * FROM Comment ORDER BY created DESC")
            comments = raw_comments.iter()
            self.render_front(file_path, comment_notification=comment_notification, comments=comments)
        else:
            uri = "/login?referer=/comment"
            self.redirect(uri)
    def post(self):
        author = self.request.get('fullname')
        comment = self.request.get('comment_content')
        post_title = self.request.get('post_title')
        new_comment = Comment(author=author, comment=comment, post_title=post_title)
        new_comment.put()
        sleep(0.25)
        self.render_front("comment_approval.html")

class PostApproval(MainPage):
    def get(self):
        title = self.request.get("title")
        blog = self.request.get("content")
        category = self.request.get("category")
        author = self.request.get("author")

        old_post = ndb.gql("SELECT * FROM UnapprovedBlog WHERE title=:1", title)
        old_post = old_post.get()
        if author and title and blog and category:
            post = Blog(title=title, blog=blog, author=author, category=category, url=old_post.url, created=old_post.created)
            post.put()
            old_post.key.delete()
            sleep(0.25)
            self.redirect("/post")
        else:
            old_post.key.delete()
            sleep(0.25)
            self.redirect("/post")

class CommentApproval(MainPage):
    def get(self):
        author = self.request.get('fullname')
        comment = self.request.get('comment_content')
        post_title = self.request.get('post_title')
        old_comment = ndb.gql("SELECT * FROM Comment WHERE post_title=:1", post_title)
        old_comment = old_comment.get()
        if author and comment:
            approved_comment = ApprovedComment(author=author, comment=comment, post_title=post_title, created=old_comment.created)
            approved_comment.put()
            old_comment.key.delete()
            sleep(0.4)
            self.redirect("/comment")
        else:
            old_comment.key.delete()
            sleep(0.4)
            self.redirect("/comment")

class ArchiveHandler(MainPage):
    def get(self):
        raw_archives = ndb.gql("SELECT * FROM Blog ORDER BY created DESC")
        archives = raw_archives.iter()

        y2015 = []
        #y2015 = []
        #y2016 = []

        for a in archives:
            if a.created.year == 2015:
                y2015 += [a]
            """elif a.created.year == 2016:
                y2016 += [a]"""

        winter = []
        spring = []
        summer = []
        fall = []

        for p in y2015:
            if p.created.month == 1 or p.created.month == 2 or p.created.month == 12:
                winter += [p]
            elif p.created.month == 3 or p.created.month == 4 or p.created.month == 5:
                spring += [p]
            elif p.created.month == 6 or p.created.month == 7 or p.created.month == 8:
                summer += [p]
            elif p.created.month == 9 or p.created.month == 10 or p.created.month == 11:
                fall += [p]

        #seasons14 = [winter, spring, summer, fall]

        if self.request.url.endswith('2015'):
            self.render_front(file_path, showcases=y2015)
        elif self.request.url.endswith('winter'):
            self.render_front(file_path, showcases=winter)
        elif self.request.url.endswith('spring'):
            self.render_front(file_path, showcases=spring)
        elif self.request.url.endswith('summer'):
            self.render_front(file_path, showcases=summer)
        elif self.request.url.endswith('fall'):
            self.render_front(file_path, showcases=fall)
    def render_front(self, file_path, showcases):
        permalink_list = self.permalink_generator()
        self.render(file_path, showcases=showcases, permalink_list=permalink_list)

class NewPostHandler(MainPage):
    update_notification = True
    def get(self):
        self.render_front(file_path, update_notification=self.update_notification)
    def post(self):
        title = self.request.get("title")
        blog = self.request.get("content")
        category = self.request.get("category")
        author = self.request.get("author")

        url = urllib2.quote(title)

        if title and blog and category and author:
            a = UnapprovedBlog(title=title, blog=blog, url=url,author=author, category=category)
            a.put()
            self.render_front("post_approval.html")
        else:
            error_message = "You have enter a title and a blog!"
            self.render_front(file_path, title=title, blog=blog, url=url, category=category,
                              author=author, error_message=error_message, update_notification=self.update_notification)
class AuthorNewPostHandler(MainPage):
    update_notification = True
    def get(self):
        if self.user:
            self.render_front(file_path, update_notification=self.update_notification)
        else:
            uri = "/login?referer=/newpost"
            self.redirect(uri)

    def post(self):
        title = self.request.get("title")
        blog = self.request.get("content")
        category = self.request.get("category")
        author = self.request.get("author")

        url = urllib2.quote(title)

        if title and blog and category and author:
            a = Blog(title=title, blog=blog, url=url,author=author, category=category)
            a.put()
            new_blog_page = "/subject?subject=" + url
            sleep(0.3)
            self.redirect(new_blog_page)
        else:
            error_message = "You have enter a title and a blog!"
            self.render_front(file_path, title=title, blog=blog, url=url, category=category,
                              author=author, error_message=error_message, update_notification=self.update_notification)

class CategoryHandler(MainPage):
    def get(self):
        raw_posts = ndb.gql("SELECT * FROM Blog ORDER BY category")
        posts = raw_posts.iter()

        algorithms = []
        poems = []
        reflections = []

        for p in posts:
            if p.category == 'Reflection':
                reflections += [p]
            elif p.category == 'Poem':
                poems += [p]
            elif p.category == 'Algorithm':
                algorithms += [p]

        all_categories = raw_posts.fetch(limit=1000)

        if self.request.url.endswith("all"):
            self.render_front(file_path, the_category=all_categories)
        elif self.request.url.endswith("algorithms"):
            self.render_front(file_path, the_category=algorithms)
        elif self.request.url.endswith("poems"):
            self.render_front(file_path, the_category=poems)
        elif self.request.url.endswith("reflections"):
            self.render_front(file_path, the_category=reflections)

    def render_front(self, file_path, the_category):
        permalink_list = self.permalink_generator()
        self.render(file_path, the_category=the_category, permalink_list=permalink_list)

class SearchHandler(MainPage):
    def get(self):
        search_keyword = self.request.get("searchkeyword")
        search_keyword = urllib2.quote(search_keyword)
        self.redirect(str("https://google.com/#q=site:muslimturkeclectic.appspot.com+" + search_keyword))

class AuthorHandler(MainPage):
    def get(self):
        permalink_list = self.permalink_generator()
        self.render(file_path, permalink_list=permalink_list, author="whitehood")

class RegisterHandler(MainPage):
    def get(self):
        username = self.request.get("username")
        password = self.request.get("password")
        password_check = self.request("password_check")


##### user stuff
def make_salt(length = 12):
    return ''.join(random.choice(letters+digits) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return ndb.Key('users', group)

class User(ndb.Model):
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.query().filter(User.name == name).get()
        return u

    @classmethod
    def register(cls, name, pw):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Login(MainPage):
    def get(self):
        referer = self.request.get('referer')
        self.render_front(file_path, referer=referer, login_notification=True)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        referer = self.request.get('referer')
        referer = referer.replace('&', '%26')
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect(referer)
        else:
            msg = 'Invalid login'
            self.render_front(file_path, username=username, login_error = msg, login_notification=True)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

class JsonHandler(MainPage):
    all_posts = ndb.Query()
    def get(self):
        all_posts = ndb.gql('SELECT * From Blog ORDER BY created ASC')
        all_posts = all_posts.iter()
        json_dict = {}
        index = 1

        for post in all_posts:
            entry_index = 'post' + str(index)
            json_dict[entry_index] = post.as_dict()
            index += 1

        self.render_json(json_dict)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/subject', SubjectHandler),
                               ('/categories', CategoryHandler),
                               ('/archive', ArchiveHandler),
                               ('/authornewpost', AuthorNewPostHandler),
                               ('/newpost', NewPostHandler),
                               ('/post', PostHandler),
                               ('/postapproval', PostApproval),
                               ('/comment', CommentHandler),
                               ('/commentapproval', CommentApproval),
                               ('/search', SearchHandler),
                               ('/author', AuthorHandler),
                               ('/register', RegisterHandler),
                               ('/login', Login),
                               ('/json', JsonHandler)
], debug=True)