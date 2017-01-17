from google.appengine.ext import ndb

from user_models import *


class BlogPost(ndb.Model):

    """Creates a Model for Blog Post"""

    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    author = ndb.StructuredProperty(User)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
