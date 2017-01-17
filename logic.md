## Edit Logic

- Create an edit template
- Use same page as new post
- Pre populate the data in existing fields
- Resubmit the post
- Update the DB overriding the previous one
- Learn how to do it using AJAX

## Authentication and Authorization
- Does user exist
- if yes, are they the author of the post
- use cookie info for login

## Delete Logic
- Fetch the id of the post
- Validate cookie
- If author, allow to delete
- If not, redirect to signup page
- In viewpost.html page:
    - Create a form
    - add a post method
    - redirect to a particular page in form action

## Comments Logic
- Registered user to comment
- More than one comment per blog.
- Associate blog post
- form action - new comments
- make sure that you put all functionality in their handler
- edit, make, delete
- 3 variables for a comment: comment, user, post
- create a new model for comments

## Other improvements
- Use python modules
- use decorators
- Use validator methods in the base class