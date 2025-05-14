import jwt
import logging
from datetime import datetime, timedelta

from ckan.lib.mailer import mail_user, MailerException
import ckan.lib.authenticator as authenticator
from ckan.plugins import toolkit as tk


log = logging.getLogger(__name__)


def user_login(context, data_dict):
    session = context["session"]

    # Adapted from  https://github.com/ckan/ckan/blob/master/ckan/views/user.py#L203-L211
    generic_error_message = {
        "errors": {"auth": [tk._("Username or password entered was incorrect")]},
        "error_summary": {tk._("auth"): tk._("Incorrect username or password")},
    }

    if not data_dict.get("id") or not data_dict.get("password"):
        return generic_error_message

    model = context["model"]
    if "@" in data_dict.get("id", ""):
        user = (
            session.query(model.User)
            .filter(model.User.email == data_dict.get("id", ""))
            .first()
        )
    else:
        user = model.User.get(data_dict["id"])

    if not user:
        return generic_error_message

    user = user.as_dict()

    if tk.config.get("ckanext.auth.include_frontend_login_token", False):
        user = generate_token(context, user)

    if data_dict["password"]:
        identity = {"login": user["name"], "password": data_dict["password"]}

        auth = authenticator

        try:
            authUser = auth.default_authenticate(identity)
            authUser_name = model.User.get(authUser.id).name

            if authUser_name != user["name"]:
                return generic_error_message
            else:
                return user
        except Exception as e:
            log.error(e)
            return generic_error_message


def generate_token(context, user):
    context["ignore_auth"] = True
    user["frontend_token"] = None

    try:
        api_tokens = tk.get_action("api_token_list")(context, {"user_id": user["name"]})

        for token in api_tokens:
            if token["name"] == "frontend_token":
                tk.get_action("api_token_revoke")(context, {"jti": token["id"]})

        frontend_token = tk.get_action("api_token_create")(
            context, {"user": user["name"], "name": "frontend_token"}
        )

        user["frontend_token"] = frontend_token.get("token")

    except Exception as e:
        log.error(e)

    return user


def user_password_reset_request(context, data_dict):
    """
    Sends a password reset email to the user with a reset link.
    """
    model = context["model"]
    user_email = data_dict.get("email")

    if not user_email:
        
        raise tk.ValidationError({"email": [tk._("Email is required")]})

    user = model.User.by_email(user_email)
    if not user:
        raise tk.ObjectNotFound(tk._("User with this email does not exist"))

    # Load configuration values
    encode_key = tk.config.get("api_token.jwt.encode.secret")
    encode_algorithm = tk.config.get("api_token.jwt.algorithm", "HS256")

    if not encode_key:
        raise tk.ValidationError({"error": [tk._("JWT secret key is not configured")]})

    # Generate a JWT token with an expiration time
    payload = {
        "email": user_email,
        "exp": datetime.utcnow() + timedelta(hours=24),  # Token valid for 24 hours
    }
    reset_token = jwt.encode(payload, encode_key, algorithm=encode_algorithm)

    # Save the token in the user model
    user.reset_key = reset_token
    user.save()

    # Generate the reset link
    frontend_url = tk.config.get("ckanext.auth.frontend_url").rstrip("/")
    reset_link = f"{frontend_url}/auth/forgot-password?token={reset_token}"

    # Render the email template
    body_html = tk.render(
        "emails/paasword_reset_template.html",
        {
            "reset_link": reset_link,
            "user_name": user.fullname or user.name,
            "site_title": tk.config.get("ckan.site_title"),
        },
    )
    # Send the email
    try:
        mail_user(
            user,
            subject="Password Reset Request",
            body="",
            body_html=body_html,
        )
    except MailerException as e:
        raise tk.ValidationError({"email": [f"Failed to send email: {str(e)}"]})

    return {"success": True, "message": tk._("Password reset email sent successfully")}


def user_password_reset_confirm(context, data_dict):
    """
    Confirms the password reset by validating the token and updating the password.
    """
    model = context["model"]
    reset_token = data_dict.get("token")
    new_password = data_dict.get("new_password")

    if not reset_token or not new_password:
        raise tk.ValidationError(
            {
                "token": [tk._("Reset token is required")],
                "new_password": [tk._("New password is required")],
            }
        )

    if len(new_password) < 8:
        raise tk.ValidationError(
            {"new_password": [tk._("Password must be at least 8 characters long")]}
        )

    # Load configuration values
    decode_key = tk.config.get("api_token.jwt.decode.secret")
    encode_algorithm = tk.config.get("api_token.jwt.algorithm", "HS256")

    if not decode_key:
        raise tk.ValidationError({"error": [tk._("JWT secret key is not configured")]})

    try:
        # Decode the JWT token
        payload = jwt.decode(reset_token, decode_key, algorithms=[encode_algorithm])
        user_email = payload.get("email")
    except jwt.ExpiredSignatureError:
        raise tk.ValidationError({"token": [tk._("Reset token has expired")]})
    except jwt.InvalidTokenError:
        raise tk.ValidationError({"token": [tk._("Invalid reset token")]})

    # Find the user by email
    user = model.User.by_email(user_email)
    if not user or user.reset_key != reset_token:
        raise tk.ObjectNotFound(
            tk._("User with this email does not exist or token is invalid")
        )

    # Update the user's password and clear the reset key
    user.password = new_password
    user.reset_key = None
    user.save()

    return {"success": True, "message": tk._("Password has been reset successfully")}
