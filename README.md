Use CKAN Classic as an auth service in your application.

It adds a new `user_login` action to the CKAN API so that you can call it for authentication of a user:

* Method: POST
* Endpoint: `http://ckan:5000/api/3/action/user_login`
* Headers: `Authorization` with sysadmin API key
* Body: `{"id": <username>, "password": <password>}`

Example of using it in the NodeJS app:

```javascript
const loginViaCKAN = async function(body) {
   // Call `user_login` action here
}

app.post("/login", async (req, res) => {
   const loggedUser = await loginViaCKAN(req.body)
   if (loggedUser) {
      // Add logged user to session
      req.session.ckan_user = loggedUser
      res.redirect('/dashboard')
   } else {
      req.flash('error_messages', 'Invalid username or password.')
      res.redirect('/login')
   }
})
```

## Requirements

This has been tested on CKAN v2.8.2.

## Installation

To install ckanext-auth:

1. Activate your CKAN virtual environment, for example::

     . /usr/lib/ckan/default/bin/activate

2. Install the ckanext-auth Python package into your virtual environment::

     pip install --no-cache-dir -e git+https://github.com/datopian/ckanext-auth.git#egg=ckanext-auth

3. Add ``auth`` to the ``ckan.plugins`` setting in your CKAN
   config file (by default the config file is located at
   ``/etc/ckan/default/production.ini``).

4. Restart CKAN. For example if you've deployed CKAN with Apache on Ubuntu::

     sudo service apache2 reload
