# this is a WIP python package to enable firebase auth with graphql django <br>
1- download the package and put it in site-packages<br>
2- add firebase_uid to the user model<br>
3- add firebase-admin in core app<br>
4- import it in shortcuts.py<br>
5- add 'django.contrib.auth.middleware.AuthenticationMiddleware' in the middleware<br>
6- Add following django apps to INSTALLED_APPS:<br>
<br>
INSTALLED_APPS = [<br>
    'django.contrib.auth',<br>
    'django.contrib.contenttypes',<br>
    'django.contrib.sessions',<br>
    ...,<br>
]<br>
7-Add JSONWebTokenBackend backend to your AUTHENTICATION_BACKENDS:<br>
<br>
AUTHENTICATION_BACKENDS = [<br>
    '[package name].backends.JSONWebTokenBackend',<br>
    'django.contrib.auth.backends.ModelBackend',<br>
]<br>
