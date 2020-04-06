import ckan.logic as logic
import ckan.lib.authenticator as authenticator
from ckan.plugins import toolkit as tk
from ckan.common import _

_check_access = logic.check_access

def user_login(context, data_dict):
    # Adapted from  https://github.com/ckan/ckan/blob/master/ckan/views/user.py#L203-L211
    model = context['model']
    user = model.User.get(data_dict['id']).as_dict()

    if data_dict[u'password']:
        identity = {
            u'login': user['name'],
            u'password': data_dict[u'password']
        }

        auth = authenticator.UsernamePasswordAuthenticator()
        authUser = auth.authenticate(context, identity)

        if authUser != user['name']:
            return {
                u'errors': {
                    u'password': [_(u'Password entered was incorrect')]
                },
                u'error_summary': {_(u'Password'): _(u'incorrect password')}
            }
        else:
            return user
