# this is a WIP python package to enable firebase auth with graphql django 
1- download the package and put it in site-packages
2- add firebase_uid to the user model
3- add firebase-admin in core app
4- import it in shortcuts.py
5- add 'django.contrib.auth.middleware.AuthenticationMiddleware' in the middleware
6- Add following django apps to INSTALLED_APPS:

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    ...,
]
7-Add JSONWebTokenBackend backend to your AUTHENTICATION_BACKENDS:

AUTHENTICATION_BACKENDS = [
    '[package name].backends.JSONWebTokenBackend',
    'django.contrib.auth.backends.ModelBackend',
]
