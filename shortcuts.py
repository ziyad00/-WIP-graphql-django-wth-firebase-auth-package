from strawberry_django_jwt.refresh_token.shortcuts import (
    create_refresh_token,
    get_refresh_token,
)
from strawberry_django_jwt.settings import jwt_settings
from strawberry_django_jwt.utils import (
    get_payload,
    get_user_by_payload,
    get_user_by_payload_async,
)
from Platform.firebase_init import firebase_app
from firebase_admin import auth
import django.contrib.auth as django_auth

User = django_auth.get_user_model()

__all__ = [
    "get_token",
    "get_user_by_token",
    "get_user_by_token_async",
    "get_refresh_token",
    "create_refresh_token",
]


def get_token(user, context=None, **extra):
    payload = jwt_settings.JWT_PAYLOAD_HANDLER(user, context)
    for k, v in extra.items():
        setattr(payload, k, v)
    return jwt_settings.JWT_ENCODE_HANDLER(payload, context)


def chech_auth(token: str):
    try:
        user_object = auth.verify_id_token(token)
        print(user_object)
        return user_object
    except jwt.InvalidTokenError:
        raise exceptions.JSONWebTokenError(_("Invalid token"))
    except Exception:
        raise exceptions.JSONWebTokenError(_("Invalid token"))


def check_user_created(user_object: str):
    firebase_uid, name, email = user_object['user_id'], user_object['name'], user_object['email']
    user = User.objects.get(firebase_uid=firebase_uid)
    if user is not None:
        return user
    else:
        new_user = User.objects.create(
            name=name, email=email, firebase_uid=firebase_uid)
        return new_user


def get_user(token):
    user_id = chech_auth(token)
    user = check_user_created(user_id)
    return user


def get_user_by_token(token, context=None):
    # payload = get_payload(token, context)
    # return get_user_by_payload(payload)
    return get_user(token)


async def get_user_by_token_async(token, context=None):
    # payload = get_payload(token, context)
    # return await get_user_by_payload_async(payload)
    return get_user(token)
