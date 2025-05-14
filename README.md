# 🔐 Using CKAN as an Authentication Service

This extension allows you to use CKAN as an authentication provider for third-party applications. It adds a new endpoint for user authentication and a secure password reset workflow using JWT tokens.

## ✨ Features

- Authenticate users via the `user_login` API
- Secure password reset workflow using JWT tokens
- Optional frontend token generation for seamless integration

## 🔧 Installation

1. **Activate your CKAN virtual environment**:

   ```bash
   . /usr/lib/ckan/default/bin/activate
   ```

2. **Install the extension**:

   ```bash
   pip install --no-cache-dir -e git+https://github.com/datopian/ckanext-auth.git#egg=ckanext-auth
   ```

3. **Enable the plugin** by adding it to your CKAN config file (`/etc/ckan/default/production.ini`):

   ```ini
   ckan.plugins = ... auth
   ```

4. **Restart CKAN** (if using Apache on Ubuntu):

   ```bash
   sudo service apache2 reload
   ```

## 🔑 User Login API

Use the `user_login` action to authenticate users from third-party applications.

- **Method**: `POST`
- **Endpoint**: `http://ckan:5000/api/3/action/user_login`
- **Request Body**:

  ```json
  {
    "id": "<username>",
    "password": "<password>"
  }
  ```

## ⚙️ Configuration Options

### `ckan.ini` Settings:

```ini
# URL used in password reset email links
ckanext.bhutanopendata.frontend_url = http://example.com/

# Generate a frontend token on login
ckanext.auth.include_frontend_login_token = True
# NOTE: This is optional. If set to True, a frontend token will be generated and included in the login response, you can use this token to authenticate users in your frontend application.
```

### ✅ User login Flow

- **Endpoint**:
  `POST /api/3/action/user_login`
- **Request Body**:

  ```json
  {
    "id": "<username>",
    "password": "<password>"
  }
  ```

- **Responses**:

  - **Success**:

    ```json
    {
      "success": true,
      "result": {
        "id": "<user_id>",
        "name": "<username>",
        "email": "<user_email>",
        "frontend_token": "<frontend_token>"
      }
    }
    ```
Below is an example of how to implement this in a Node.js application using Express.

```javascript
const loginViaCKAN = async function (body) {
  const response = await fetch("http://ckan:5000/api/3/action/user_login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const result = await response.json();
  return result.success ? result.result : null;
};

app.post("/login", async (req, res) => {
  const loggedUser = await loginViaCKAN(req.body);
  if (loggedUser) {
    req.session.ckan_user = loggedUser;
    res.redirect("/dashboard");
  } else {
    req.flash("error_messages", "Invalid username or password.");
    res.redirect("/login");
  }
});
```

## 🔄 Password Reset Flow

### 1. **Request Reset Email**

- **Endpoint**:
  `POST /api/3/action/user_password_reset_request`

- **Request Body**:

  ```json
  {
    "email": "user@example.com"
  }
  ```

- **Responses**:

  - **Success**:

    ```json
    {
      "success": true,
      "message": "Password reset email sent"
    }
    ```

  - **Errors**:

    ```json
    {
      "error": {
        "email": ["Email is required"]
      }
    }
    ```

    ```json
    {
      "error": {
        "message": "User with this email does not exist"
      }
    }
    ```

---

### 2. **Confirm Password Reset**

- **Endpoint**:
  `POST /api/3/action/user_password_reset_confirm`

- **Request Body**:

  ```json
  {
    "token": "jwt_token_here",
    "new_password": "new_secure_password"
  }
  ```

- **Responses**:

  - **Success**:

    ```json
    {
      "success": true,
      "message": "Password has been reset successfully"
    }
    ```

  - **Errors**:

    ```json
    {
      "error": {
        "token": ["Token is required"],
        "new_password": ["New password is required"]
      }
    }
    ```

    ```json
    {
      "error": {
        "token": ["Reset token has expired"]
      }
    }
    ```


