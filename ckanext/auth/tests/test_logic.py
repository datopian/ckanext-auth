import pytest

import ckan.lib.navl.dictization_functions as df
from ckan import model
import ckan.tests.factories as factories
import ckanext.auth.logic as auth_logic


@pytest.mark.usefixtures('with_plugins', 'test_request_context')
def test_login():
    userobj = factories.Sysadmin(password='testpass1234')
    session = model.Session
    context = {
        'model': model,
        'session': session,
        'user': userobj['name'],
        'ignore_auth': True,
        'user_obj': userobj,
    }
    print(context)

    login = auth_logic.user_login(
        context=context,
        data_dict={
            'id': userobj['id'],
            'password': 'testpass1234'
        }
    )

    assert login['name'] == userobj['name']
