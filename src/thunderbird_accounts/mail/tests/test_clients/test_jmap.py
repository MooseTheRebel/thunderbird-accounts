import json
from pathlib import Path
from typing import Literal
from unittest.mock import MagicMock, call, patch

from django.test import SimpleTestCase, override_settings

from thunderbird_accounts.mail.clients.jmap_client import JMAPClient
from thunderbird_accounts.mail.clients.mail_client_jmap import MailClientAdminJMAP
from thunderbird_accounts.mail.exceptions import DomainNotFoundError
from thunderbird_accounts.mail.tests.test_clients.test_legacy import (
    TestMailClientCheckDomainDNS,
)
from thunderbird_accounts.mail.types.jmap import Invocation, JMapRequest, JMapResponse, SessionResource
from thunderbird_accounts.mail.types import stalwart
from thunderbird_accounts.mail.types.stalwart import StalwartMethods


class MockJMapClient(JMAPClient):
    def retrieve_fixture(self, fixture_path: Path) -> dict:
        fixture_path = Path(__file__).parent.parent.joinpath(fixture_path)
        with open(fixture_path, 'r') as fh:
            data = json.loads(fh.read())
        return data

    def get_session(self) -> SessionResource:
        if self.session:
            return self.session

        fixture_data = self.retrieve_fixture(Path('fixtures') / 'jmap_get_session.json')
        session = SessionResource(**fixture_data)
        self.session = session
        if not self.session:
            raise RuntimeError('Failed to get session')
        self.api_url = session.api_url
        return session

    def request(self, request_data: JMapRequest, method: Literal['get', 'post'] = 'post') -> JMapResponse:
        raise NotImplementedError('Monkeypatch me!')


def build_admin_client() -> MailClientAdminJMAP:
    """Build a MailClientAdminJMAP that never touches the network.

    ``MailClientAdminJMAP.__init__`` builds a real ``JMAPClient`` and eagerly fetches the session
    resource over HTTP, so patch ``_get_user_client`` for the duration of construction to hand back
    a ``MockJMapClient`` (which reads the session from a fixture) instead.
    """

    def _mock_user_client(self, *args, **kwargs) -> MockJMapClient:
        client = MockJMapClient('http://stalwart.local', 'admin', 'admin')
        client.get_session()
        return client

    with patch.object(MailClientAdminJMAP, '_get_user_client', _mock_user_client):
        return MailClientAdminJMAP()


@override_settings(
    STALWART_BASE_API_URL='http://stalwart.test',
    STALWART_API_AUTH_STRING='secret',
    STALWART_API_AUTH_METHOD='bearer',
    CONNECTION_INFO={'SMTP': {'HOST': 'mail.test.com'}},
    SPF_HOST='spf.test.com',
    HOSTED_DKIM_DOMAIN='dkim.test.net',
    HOSTED_DKIM_SELECTORS=['tm1', 'tm2'],
)
class TestCheckDomainDNS(TestMailClientCheckDomainDNS):
    def setUp(self):
        self.mail_client = build_admin_client()
        self.domain = 'example.com'
        self.expected_host = 'mail.test.com'


class TestCreateDkim(SimpleTestCase):
    def setUp(self):
        self.mail_client = build_admin_client()
        self.mail_client.preflight_check = MagicMock()
        self.domain = 'example.com'
        self.expected_host = 'mail.test.com'

    @override_settings(
        STALWART_DKIM_ALGOS=['Ed25519', 'Rsa'],
        STALWART_DKIM_ALGO_SELECTORS={'Rsa': 'tm1', 'Ed25519': 'tm2'},
        STALWART_DKIM_STAGE_MANAGEMENT_ENABLED=True,
    )
    @patch('uuid.uuid4')
    @patch('thunderbird_accounts.mail.tests.test_clients.test_jmap.MockJMapClient.request')
    def test_success(self, requests_mock: MagicMock, uuid4_mock: MagicMock):
        temp_id = 'abc123'
        uuid4_mock.return_value = temp_id

        domain_response = stalwart.Domain(
            id='a',
            name=self.domain,
            is_enabled=True,
            aliases={},
            created_at='2026-07-08T20:45:29Z',
            certificate_management={'@type': 'Automatic'},
            dkim_management={'@type': 'Manual'},
            dns_management={'@type': 'Manual'},
            dns_zone_file='',
            sub_addressing={'@type': 'Enabled'},
            allow_relaying=True,
        ).model_dump()

        # I'm lazy, and we don't really need the first method response
        get_domain_response = JMapResponse(
            method_responses=[
                Invocation(name='x:Query/Domain', arguments={'ids': ['a']}, method_call_id='0'),
                Invocation(name='x:Get/Domain', arguments={'list': [domain_response]}, method_call_id='1'),
            ],
            session_state='a',
        )
        create_dkim_response = JMapResponse(
            method_responses=[
                Invocation(
                    name='x:Set/DkimSignature',
                    arguments={
                        'accountId': 'd333333',
                        'created': {temp_id: {'id': 'i3cjmrt2acac'}},
                    },
                    method_call_id='0',
                ),
            ],
            session_state='a',
        )
        requests_mock.side_effect = [get_domain_response, create_dkim_response, create_dkim_response]

        # Requests:
        # 1. get domain
        # 2. set dkim (Ed25519)
        # 3. set dkim (Rsa)
        response_data = self.mail_client.create_dkim(self.domain)

        self.assertIsNotNone(response_data)
        self.assertEqual(3, requests_mock.call_count)


class TestDeleteDomain(SimpleTestCase):
    def setUp(self):
        self.mail_client = build_admin_client()
        self.mail_client.preflight_check = MagicMock()
        self.domain = 'customdomain.com'

    def test_deletes_dkim_signatures_before_domain(self):
        """Unlike the legacy client, delete_domain also calls delete_dkim."""
        manager = MagicMock()
        manager.get_domain.return_value = MagicMock(id='a')

        with (
            patch.object(self.mail_client, 'get_domain', manager.get_domain),
            patch.object(self.mail_client, 'delete_dkim', manager.delete_dkim),
            patch.object(self.mail_client, '_handle_destroy', manager._handle_destroy),
        ):
            self.assertIsNone(self.mail_client.delete_domain(self.domain))

        self.assertEqual(
            [
                call.get_domain(self.domain),
                call.delete_dkim(self.domain),
                call._handle_destroy(StalwartMethods.DOMAIN, 'a'),
            ],
            manager.mock_calls,
        )

    def test_not_found_raises_domain_not_found(self):
        with (
            patch.object(self.mail_client, 'get_domain', side_effect=DomainNotFoundError(self.domain)),
            patch.object(self.mail_client, 'delete_dkim') as delete_dkim_mock,
            patch.object(self.mail_client, '_handle_destroy') as handle_destroy_mock,
        ):
            with self.assertRaises(DomainNotFoundError):
                self.mail_client.delete_domain(self.domain)

        delete_dkim_mock.assert_not_called()
        handle_destroy_mock.assert_not_called()

    def test_domain_without_id_raises_domain_not_found(self):
        with (
            patch.object(self.mail_client, 'get_domain', return_value=MagicMock(id=None)),
            patch.object(self.mail_client, 'delete_dkim') as delete_dkim_mock,
            patch.object(self.mail_client, '_handle_destroy') as handle_destroy_mock,
        ):
            with self.assertRaises(DomainNotFoundError):
                self.mail_client.delete_domain(self.domain)

        delete_dkim_mock.assert_not_called()
        handle_destroy_mock.assert_not_called()
