import logging

import ckan.lib.authenticator as authenticator
from ckan.common import _


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
