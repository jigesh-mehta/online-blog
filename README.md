# online-blog

A fully functional blog deployed on [google app engine](http://jigesh-mehta.appspot.com/blog). Any visitor can view blogs. A registered user could login and post a new blog.

Features of the blog:
* Used hashing to securely read and transmit user passwords
* Secure storage of passwords using random salt value for each user
* Blog data can be generated in json format
* Used memcache in order to cache pages for serving requests faster

Technologies used: *Python, memcache, webapp2, jinja2*