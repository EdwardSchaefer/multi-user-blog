This application creates a multi-user blog using Python/webapp2 in 
conjunction with Google App Engine as well as using Jinja2 templates and 
css for styling. Users can sign up via the signup form. User passwords are 
securely stored with a hashing algorithm. Once they are logged in, they can 
like other user's posts, and edit and delete their own. A registered user can 
comment on any post. 

The blog is currently active at the following URL:
https://multi-user-blog-155223.appspot.com/blog

#List of files
--------------

	*blog.py: The main python file, defining the functions of the blog
	*templates/base.html: Provides a framework that the other templates build 
	on, as well as displaying the user name and links to login and sign-up.
	*templates/comments.html: Renders the comments via front.html 
	or permalink.html
	*templates/edit.html: Renders the edit form for users to edit their own 
	posts
	*templates/front.html: Displays all of the posts, with the most recent 
	first
	*templates/login-form.html: A form for users to login to their accounts
	*templates/newpost.html: A form to create a new post
	*templates/permalink.html: Displays the post specified in the handler, 
	as well as a comment form.
	*templates/post.html: Render the content of the post. post.html is 
	rendered within front.html or permalink.html
	*templates/signup-form.html: A form visitors use to sign up for an account
	*static/main.css: Contains the css styles for the blog
	*index.yaml: Provides indexes for Google App Engine
	*app.yaml: The yaml configuration file for the app. This file is required 
	for Google App engine applications.
	*README.md: this readme file

#List of changes
----------------
	*1/10/2017: Added URL of active blog to README.MD
	*1/9/17: Removed "application" and "version" fields from app.yaml, as they
	are no longer supported by Google App Engine