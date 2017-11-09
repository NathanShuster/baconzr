# baconzr
Code for an basic, but functional forum that I made for my high school programming teammates back in 2014. Backend is GAE's webapp2 w/memcache and templates are handled by jinja2. Includes code for users, posts, comments on posts, basic security (salted and hashed password storage), and (basic) version control for the team code.

The name for this project comes from our team, BACON (Best All-round Club Of Nerds) and the competition it was designed for, <a href="http://zerorobotics.mit.edu/">ZeroRobotics</a> (abbreviated ZR).

### Install

First install Google App Engine Launcher and the Google App Engine SDK. 
- https://cloud.google.com/appengine/docs/flexible/python/download

This project requires **Python 2.7** and the following libraries installed:
- Jinja2 http://jinja.pocoo.org/docs/2.10/

### Run

Launch main.py within the directory from the Google App Engine Launcher. Then, to view the running local version point your browser to http://localhost:8080.
