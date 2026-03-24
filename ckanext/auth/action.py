import jwt
import logging
from datetime import datetime, timedelta

from ckan.lib.mailer import mail_user, MailerException
import ckan.lib.authenticator as authenticator
import ckan.lib.redis as ckan_redis
from ckan.plugins import toolkit as tk


log = logging.getLogger(__name__)

_RESEND_EMAIL_COOLDOWN = 60   # seconds between sends per email
_RESEND_IP_MAX = 5            # max requests per IP per window
_RESEND_IP_WINDOW = 300       # IP window in seconds


def _check_resend_rate_limit(email, ip):
    redis = ckan_redis.connect_to_redis()

    # Per-email cooldown: SET NX with TTL — only succeeds on first request
    email_key = f"ckanext_auth:resend_cooldown:{email}"
    if not redis.set(email_key, 1, nx=True, ex=_RESEND_EMAIL_COOLDOWN):
        raise tk.ValidationError(
            {"email": [tk._("Please wait before requesting another verification email")]}
        )

    # Per-IP burst limit: INCR counter, set TTL on first hit
    if ip:
        ip_key = f"ckanext_auth:resend_ip:{ip}"
        count = redis.incr(ip_key)
        if count == 1:
            redis.expire(ip_key, _RESEND_IP_WINDOW)
        if count > _RESEND_IP_MAX:
            # Roll back the email cooldown key so a legitimate user isn't blocked
            redis.delete(email_key)
            raise tk.ValidationError(
                {"email": [tk._("Too many requests. Please try again later.")]}
            )


def _generate_verification_token(user_id):
    encode_key = tk.config.get("api_token.jwt.encode.secret")
    encode_algorithm = tk.config.get("api_token.jwt.algorithm", "HS256")

    if not encode_key:
        raise tk.ValidationError({"error": [tk._("JWT secret key is not configured")]})

    expiry_hours = int(tk.config.get("ckanext.auth.email_verification_expiry_hours", 24))
    payload = {
        "user_id": user_id,
        "purpose": "email_verification",
        "exp": datetime.utcnow() + timedelta(hours=expiry_hours),
    }
    return jwt.encode(payload, encode_key, algorithm=encode_algorithm)


def _send_verification_email(user_obj):
    token = _generate_verification_token(user_obj.id)
    frontend_url = tk.config.get("ckanext.auth.frontend_url", "").rstrip("/")
    verify_url = f"{frontend_url}/auth/verify-email?token={token}"

    body_html = tk.render(
        "emails/email_verification_template.html",
        {
            "verify_url": verify_url,
            "user_name": user_obj.fullname or user_obj.name,
            "site_title": tk.config.get("ckan.site_title"),
        },
    )

    try:
        mail_user(
            user_obj,
            subject="Verify your email address",
            body="",
            body_html=body_html,
        )
    except MailerException as e:
        raise tk.ValidationError({"email": [f"Failed to send verification email: {str(e)}"]})


def user_register(context, data_dict):
    """
    Self-registration endpoint. Creates a new user, sets state to pending,
    and sends a verification email.

    user_create (called by sysadmins) and user_invite do not go through
    this flow and are not affected.
    """
    context["ignore_auth"] = True
    context["defer_commit"] = True
    user = tk.get_action("user_create")(context, data_dict)

    model = context["model"]
    user_obj = model.User.get(user["id"])
    user_obj.state = "pending"
    model.Session.commit()

    
    _send_verification_email(user_obj)

    return user


def user_verify_email(context, data_dict):
    """
    Verifies a user's email address using a JWT token.
    """
    token = data_dict.get("token")
    if not token:
        raise tk.ValidationError({"token": [tk._("Token is required")]})

    decode_key = tk.config.get("api_token.jwt.decode.secret")
    encode_algorithm = tk.config.get("api_token.jwt.algorithm", "HS256")

    if not decode_key:
        raise tk.ValidationError({"error": [tk._("JWT secret key is not configured")]})

    try:
        payload = jwt.decode(token, decode_key, algorithms=[encode_algorithm])
        if payload.get("purpose") != "email_verification":
            raise tk.ValidationError({"token": [tk._("Invalid token")]})
        user_id = payload.get("user_id")
    except jwt.ExpiredSignatureError:
        raise tk.ValidationError({"token": [tk._("Verification link has expired")]})
    except jwt.InvalidTokenError:
        raise tk.ValidationError({"token": [tk._("Invalid verification token")]})

    model = context["model"]
    user_obj = model.User.get(user_id)
    if not user_obj:
        raise tk.ObjectNotFound(tk._("User not found"))

    if user_obj.state == "active":
        return {"success": True, "message": tk._("Email already verified")}

    user_obj.state = "active"
    model.Session.commit()

    return {"success": True, "message": tk._("Email verified successfully. You can now log in.")}


def user_resend_verification(context, data_dict):
    """
    Resends the verification email for a pending user.
    """
    email = data_dict.get("email")
    if not email:
        raise tk.ValidationError({"email": [tk._("Email is required")]})

    try:
        ip = tk.request.remote_addr
    except RuntimeError:
        ip = None

    _check_resend_rate_limit(email, ip)

    generic_response = {"success": True, "message": tk._("If this email is registered and pending verification, a new email link has been sent")}

    model = context["model"]
    user_obj = model.User.by_email(email)
    if not user_obj or user_obj.state != "pending":
        return generic_response

    _send_verification_email(user_obj)

    return generic_response


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

    if user.state == "pending":
        return {
            "errors": {"auth": [tk._("Your account is not yet verified. Please confirm your email address to continue.")]},
            "error_summary": {tk._("auth"): tk._("Email not verified")},
        }

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
