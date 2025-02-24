import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckanext.auth.logic import user_login, user_logout

class AuthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IActions)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'auth')

    def get_actions(self):
        return {
            'user_login': user_login,
            'user_logout': user_logout,
        }
