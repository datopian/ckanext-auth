import logging
import jwt
import requests
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives import serialization
import random
import string
from sqlalchemy import func

import ckan.lib.authenticator as authenticator
from ckan.common import _, config
from ckan.plugins import toolkit


log = logging.getLogger(__name__)


def get_azure_keys(tenant_id):
    jwks_uri = f'https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys'
    response = requests.get(jwks_uri)
    jwks = response.json()

    if 'keys' not in jwks:
        raise ValueError('No "keys" found in JWKS response')

    pem_keys = {}

    for key in jwks['keys']:
        rsa_key = RSAAlgorithm.from_jwk(key)
        pem_key = rsa_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pem_keys[key['kid']] = pem_key

    return pem_keys


def validate_azure_jwt(token):
    tenant_id = config.get('ckanext.auth.azure_tenant_id')
    client_id = config.get('ckanext.auth.azure_client_id')
    issuer = f'https://login.microsoftonline.com/{tenant_id}/v2.0'

    if not tenant_id or not client_id:
        raise ValueError('Azure tenant ID or client ID not configured')

    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')
        azure_keys = get_azure_keys(tenant_id)

        if kid not in azure_keys:
            raise ValueError(f'Key ID {kid} not found in Azure JWKS')

        key = azure_keys[kid]
        decoded_token = jwt.decode(
            token,
            key=key,
            algorithms=['RS256'],
            audience=client_id,
            issuer=issuer,
            options={'verify_exp': True},
        )

        return decoded_token
    except Exception as e:
        print(f'Token validation failed: {e}')
        return None


def user_login(context, data_dict):
    session = context['session']

    # Adapted from  https://github.com/ckan/ckan/blob/master/ckan/views/user.py#L203-L211
    generic_error_message = {
        'errors': {'auth': [_('Username or password entered was incorrect')]},
        'error_summary': {_('auth'): _('Incorrect username or password')},
    }

    from_azure = data_dict.get('from_azure', False)

    if from_azure:
        jwt_token = data_dict['id_token']
        model = context['model']
        context['ignore_auth'] = True

        validated_token = validate_azure_jwt(jwt_token)
        user_email = validated_token.get('email')

        if not user_email or not validated_token:
            return generic_error_message

        user = session.query(model.User).filter(func.lower(model.User.email) == func.lower(user_email)).first()

        if not user:
            log.info(f'No user found with email {user_email}. Creating user...')
            password_length = 10
            password = ''.join(
                random.choice(string.ascii_letters + string.digits)
                for _ in range(password_length)
            )

            try:
                user_name = ''.join(
                    c.lower() if c.isalnum() else '_' for c in user_email.split('@')[0]
                )
                user = toolkit.get_action('user_create')(
                    context,
                    {
                        'name': user_name,
                        'display_name': data_dict['name'],
                        'fullname': data_dict['name'],
                        'email': user_email,
                        'password': password,
                        'state': 'active',
                    },
                )
            except Exception as e:
                log.error(f'Error creating user: \n{e}')
                return generic_error_message

            log.info(f'User created: \n{user}')
        else:
            log.info('User already exists')
            user = user.as_dict()

        if config.get('ckanext.auth.include_frontend_login_token', False):
            user = generate_token(context, user)

        return user

    generic_error_message = {
        'errors': {'auth': [_('Username or password entered was incorrect')]},
        'error_summary': {_('auth'): _('Incorrect username or password')},
    }

    if not data_dict.get('id') or not data_dict.get('password'):
        return generic_error_message

    model = context['model']
    if "@" in data_dict.get("id", ""):
        user = session.query(model.User).filter(model.User.email == data_dict.get("id", "")).first()
    else:
        user = model.User.get(data_dict['id'])

    if not user:
        return generic_error_message

    user = user.as_dict()

    if config.get('ckanext.auth.include_frontend_login_token', False):
        user = generate_token(context, user)

    if data_dict['password']:
        identity = {'login': user['name'], 'password': data_dict['password']}

        auth = authenticator

        try:
            authUser = auth.default_authenticate(identity)
            authUser_name = model.User.get(authUser.id).name

            if authUser_name != user['name']:
                return generic_error_message
            else:
                return user
        except Exception as e:
            log.error(e)
            return generic_error_message


def generate_token(context, user):
    context['ignore_auth'] = True
    user['frontend_token'] = None

    try:
        api_tokens = toolkit.get_action('api_token_list')(
            context, {'user_id': user['name']}
        )

        for token in api_tokens:
            if token['name'] == 'frontend_token':
                toolkit.get_action('api_token_revoke')(context, {'jti': token['id']})

        frontend_token = toolkit.get_action('api_token_create')(
            context, {'user': user['name'], 'name': 'frontend_token'}
        )

        user['frontend_token'] = frontend_token.get('token')

    except Exception as e:
        log.error(e)

    return user
