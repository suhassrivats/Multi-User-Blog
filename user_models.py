from google.appengine.ext import ndb


class User(ndb.Model):

    """Contains information about a user"""

    username = ndb.StringProperty(required=True)
    pwd_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
