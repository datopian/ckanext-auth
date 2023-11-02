import logging

import ckan.lib.authenticator as authenticator
from ckan.common import _, config
from ckan.plugins import toolkit


log = logging.getLogger(__name__)


def user_login(context, data_dict):
    # Adapted from  https://github.com/ckan/ckan/blob/master/ckan/views/user.py#L203-L211
    generic_error_message = {
        u'errors': {
            u'auth': [_(u'Username or password entered was incorrect')]
        },
        u'error_summary': {_(u'auth'): _(u'Incorrect username or password')}
    }

    if not data_dict.get(u'id') or not data_dict.get(u'password'):
        return generic_error_message

    model = context['model']
    user = model.User.get(data_dict['id'])

    if not user:
        return generic_error_message

    user = user.as_dict()

    if config.get('ckanext.auth.include_frontend_login_token', False):
        user = generate_token(context, user)

    if data_dict[u'password']:
        identity = {
            u'login': user['name'],
            u'password': data_dict[u'password']
        }

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
    user['login_token'] = None

    try:
        api_tokens = {}
        api_tokens = toolkit.get_action('api_token_list')(
            context,
            {'user_id': user['name']}
        )

        login_token = None

        for token in api_tokens:
            if token['name'] == 'frontend_token':
                toolkit.get_action('api_token_revoke')(
                    context,
                    {'jti': token['id']}
                )

        login_token = toolkit.get_action('api_token_create')(
            context,
            {'user': user['name'], 'name': 'frontend_token'}
        )

        user['frontend_token'] = login_token.get('token')

    except Exception as e:
        log.error(e)

    return user
