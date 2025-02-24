import pytest

import ckan.lib.navl.dictization_functions as df
from ckan import model
import ckan.tests.factories as factories
import ckanext.auth.logic as auth_logic
import ckan.plugins.toolkit as toolkit


@pytest.mark.usefixtures('with_plugins', 'test_request_context')
def test_login(app, test_request_context):
    with test_request_context():
        userobj = factories.Sysadmin(password='testpass1234')
        session = model.Session
        context = {
            'model': model,
            'session': session,
            'user': userobj['name'],
            'ignore_auth': True,
            'user_obj': userobj,
        }

        login = auth_logic.user_login(
            context=context,
            data_dict={
                'id': userobj['id'],
                'password': 'testpass1234'
            }
        )

        assert login['name'] == userobj['name']

@pytest.mark.usefixtures('with_plugins', 'test_request_context')
def test_login_w_email(app, test_request_context):
    with test_request_context():
        userobj = factories.Sysadmin(password='testpass1234')
        session = model.Session
        context = {
            'model': model,
            'session': session,
            'user': userobj['name'],
            'ignore_auth': True,
            'user_obj': userobj,
        }

        login = auth_logic.user_login(
            context=context,
            data_dict={
                'id': userobj['email'],
                'password': 'testpass1234'
            }
        )

        assert login['name'] == userobj['name']


@pytest.mark.usefixtures('with_plugins', 'test_request_context')
def test_login_wrong_password(app, test_request_context):
    with test_request_context():
        userobj = factories.Sysadmin(password='testpass1234')
        session = model.Session
        context = {
            'model': model,
            'session': session,
            'user': userobj['name'],
            'ignore_auth': True,
            'user_obj': userobj,
        }

        login = auth_logic.user_login(
            context=context,
            data_dict={
                'id': userobj['id'],
                'password': 'wrongpassword'
            }
        )

        assert login['error_summary']['auth'] == 'Incorrect username or password'


@pytest.mark.usefixtures('with_plugins', 'test_request_context')
def test_login_missing_field(app, test_request_context):
    with test_request_context():
        userobj = factories.Sysadmin(password='testpass1234')
        session = model.Session
        context = {
            'model': model,
            'session': session,
            'user': userobj['name'],
            'ignore_auth': True,
            'user_obj': userobj,
        }

        login = auth_logic.user_login(
            context=context,
            data_dict={
                'id': userobj['id'],
            }
        )

        assert login['error_summary']['auth'] == 'Incorrect username or password'


@pytest.mark.usefixtures('with_plugins', 'test_request_context')
@pytest.mark.ckan_config('ckanext.auth.include_frontend_login_token', True)
def test_login_frontend_token_enabled(app, test_request_context):
    with test_request_context():
        userobj = factories.Sysadmin(password='testpass1234')
        session = model.Session
        context = {
            'model': model,
            'session': session,
            'user': userobj['name'],
            'ignore_auth': True,
            'user_obj': userobj
        }

        login = auth_logic.user_login(
            context=context,
            data_dict={
                'id': userobj['id'],
                'password': 'testpass1234'
            }
        )

        assert login['name'] == userobj['name']
        assert login['frontend_token'] is not None

        # Check that the token is valid
        tokens = toolkit.get_action('api_token_list')(
            context,
            {'user_id': userobj['name']}
        )

        assert len(tokens) == 1
        assert tokens[0]['name'] == 'frontend_token'


@pytest.mark.usefixtures('with_plugins', 'test_request_context')
@pytest.mark.ckan_config('ckanext.auth.include_frontend_login_token', False)
def test_login_frontend_token_disabled(app, test_request_context):
    with test_request_context():
        userobj = factories.Sysadmin(password='testpass1234')
        session = model.Session
        context = {
            'model': model,
            'session': session,
            'user': userobj['name'],
            'ignore_auth': True,
            'user_obj': userobj
        }

        login = auth_logic.user_login(
            context=context,
            data_dict={
                'id': userobj['id'],
                'password': 'testpass1234'
            }
        )

        assert login['name'] == userobj['name']
        assert 'frontend_token' not in login
