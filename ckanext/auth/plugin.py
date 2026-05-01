import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckanext.auth import action


class AuthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IActions)

    # IConfigurer
    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("fanstatic", "auth")

    def get_actions(self):
        return {
            "user_login": action.user_login,
            "user_register": action.user_register,
            "user_verify_email": action.user_verify_email,
            "user_resend_verification": action.user_resend_verification,
            "user_password_reset_request": action.user_password_reset_request,
            "user_password_reset_confirm": action.user_password_reset_confirm,
        }
