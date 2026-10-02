from unittest.mock import call, patch

from django.conf import settings
from django.test import TestCase, override_settings

from thunderbird_accounts.authentication.clients import KeycloakClient
from thunderbird_accounts.authentication.exceptions import DeleteUserError
from thunderbird_accounts.authentication.models import AllowListEntry, User, UsernameBlockListEntry
from thunderbird_accounts.authentication.reserved import is_reserved
from thunderbird_accounts.authentication.utils import delete_user_data, is_email_in_allow_list
from thunderbird_accounts.mail import tasks as mail_tasks
from thunderbird_accounts.mail.clients import MailClient
from thunderbird_accounts.mail.exceptions import DomainNotFoundError
from thunderbird_accounts.mail.models import Account, Domain, Email


class IsReservedUnitTests(TestCase):
    def test_brand_names(self):
        for brand in ['thunderbird', 'thundermail', 'tbpro', 'mozilla', 'firefox', 'help', 'support', 'mzla']:
            self.assertTrue(is_reserved(brand))

    def test_brand_plus_variants(self):
        # (brands)? allows more than one match. NOTE: 'supportsupport' is now
        # reserved via the 'support' affix from admin-list.json.
        for name in ['thunderbirdthunderbird']:
            self.assertFalse(is_reserved(name))

    def test_brand_support_help_suffix_patterns(self):
        # ^(brand).*support?$ and customer_support and help
        for name in [
            'thunderbirdpro_customer_support',
            'thunderbirdpro_support',
            'thunderbird_customer_support',
            'thunderbird_support',
            'thunderbird-support',
            'mzla_support',
            'mzla_help',
            'mozilla_support',
            'firefox_help',
        ]:
            self.assertTrue(is_reserved(name))

        # ^(brand).*email?$ and ^(brand).*org?$
        for name in ['thunderbird_email', 'firefox_org']:
            self.assertTrue(is_reserved(name), name)

    def test_official_and_real_variants(self):
        for name in [
            'official_thunderbird',
            'officialsupport',
            'realmozilla',
            'firefox_real',
            'support_official',
            'mozilla_real',
        ]:
            self.assertTrue(is_reserved(name))

    def test_mzla_test_variants(self):
        for name in ['mzla-test', 'mzla-test.123', 'mzla-test.alpha.beta']:
            self.assertTrue(is_reserved(name))

    def test_common_example_usernames(self):
        for name in ['username', 'user_name', 'user', 'exampleuser', 'example_name', 'example-user', 'test']:
            self.assertTrue(is_reserved(name))

    def test_servers(self):
        for name in ['admin', 'root', 'webmaster', 'postmaster', 'superuser', 'administrator']:
            self.assertTrue(is_reserved(name))

    def test_team_and_contact(self):
        for name in [
            'team',
            'hr',
            'accounts_team',
            'engineering',
            'engineering_team',
            'marketing_team',
            'design',
            'design_team',
            'contactus',
            'contact_us',
        ]:
            self.assertTrue(is_reserved(name))

    def test_internal_names(self):
        # Representative RFC 2142 / role / server names (now covered by the
        # generated word lists rather than hardcoded in checker.py).
        for name in [
            'root',
            'postmaster',
            'hostmaster',
            'webmaster',
            'support',
            'abuse',
            'marketing',
            'noreply',
            'no-reply',
            'mailer-daemon',
            'nobody',
            'uucp',
        ]:
            self.assertTrue(is_reserved(name), name)

    def test_birbs(self):
        for name in ['roc', 'ezio', 'mithu', 'ava', 'callum', 'sora', 'robin', 'nemo']:
            self.assertTrue(is_reserved(name))

    def test_non_reserved(self):
        # NOTE: role-word affixes (e.g. 'supporter', 'helper', 'contacts',
        # 'hostmastery') are intentionally reserved now via the admin-list
        # prefix/suffix rule -- see test_affix_admin_terms_match_prefix_suffix.
        reserved_names_related = ['mozillafan']
        unrelated = ['randomuser', 'this_should_not_be_a_problem', '123_asdf', 'asdf_123', '123asdf', 'asdf123']
        for name in reserved_names_related + unrelated:
            self.assertFalse(is_reserved(name), name)

    def test_partial_matches_should_pass(self):
        # Full-string-only names that must not collide with the exact set, the
        # admin-list affix set, or the brand regex layer. 'helloadminguy' and
        # 'badminton' embed an affix term inside a single token, so they pass.
        for name in ['user123', 'myusernamex', 'teamwork', 'helloadminguy', 'badminton']:
            self.assertFalse(is_reserved(name), name)

    def test_affix_matches_separator_delimited_tokens(self):
        # An affix term that appears as a token delimited by any non-alphanumeric
        # separator is reserved, even mid-string -- but not when embedded inside
        # a token.
        for name in [
            '-admin-',
            'company-admin-team',
            'admin.billing',
            'x_postmaster_y',
            'foo.ssl.bar',
            'foo+admin+bar',
            'foo=postmaster=bar',
            'foo%webmaster%bar',
            'foo!admin!bar',
            'foo/postmaster/bar',
            "foo'ssl'bar",
            'foo~hostmaster~bar',
        ]:
            self.assertTrue(is_reserved(name), name)
        # Multi-separator terms still match by prefix/suffix on the whole string.
        for name in ['no-reply', 'company-no-reply', 'mailer-daemon']:
            self.assertTrue(is_reserved(name), name)
        # Embedded in a single token (no separators) -> still allowed.
        for name in ['helloadminguy', 'badminton']:
            self.assertFalse(is_reserved(name), name)

    def test_vendored_role_and_infra_addresses(self):
        # Forward Email (RFC 2142 + admin/no-reply) and shouldbee exact-match union.
        for name in [
            'noc',
            'dev',
            'pop',
            'ssl',
            'noreply',
            'no-reply',
            'do-not-reply',
            'mailer-daemon',
            'ns1',
            'mx',
            'webmail',
            'login',
            'password',
            'oauth',
            'webhook',
            'notifications',
            'unsubscribe',
        ]:
            self.assertTrue(is_reserved(name), name)

    def test_affix_admin_terms_match_prefix_suffix(self):
        # admin-list.json / no-reply-list.json entries match as exact, prefix,
        # or suffix (Forward Email's model).
        for name in [
            'admin',
            'adminbilling',
            'billing-admin',
            'administrator2',
            'companypostmaster',
            'postmaster-team',
            'ssl123',
            'mywebmaster',
            'hostmastery',
            'supporter',
            'helper',
            'rooted',
            'developer',
            'contacting',
        ]:
            self.assertTrue(is_reserved(name), name)

    def test_reserved_is_case_and_unicode_insensitive(self):
        # Input is NFKC-normalized + lowercased; lists carry homograph variants.
        for name in [
            'ADMIN',
            'Admin',
            'POSTMASTER',
            'аdmin',  # Cyrillic 'а'
            'αdmin',  # Greek 'α'
            'ａdmin',  # fullwidth 'ａ'
        ]:
            self.assertTrue(is_reserved(name), name)

    def test_username_block_list_entries(self):
        block_list_entries = ['skeletons', 'dog*', 'pizza']
        for name in block_list_entries:
            name = name.replace('*', '')
            self.assertFalse(is_reserved(name))

        for name in block_list_entries:
            UsernameBlockListEntry.objects.create(pattern=name)

        # Add some entries that will pass with the wildcard entry (dog)
        block_list_entries += ['dog-dog', 'dog-skeleton']
        # Add some entries that will fail the wildcard entry (dog)
        not_reserved_entries = ['skeleton-dog', 'skeletons2']

        for name in block_list_entries:
            self.assertTrue(is_reserved(name))
        for name in not_reserved_entries:
            self.assertFalse(is_reserved(name))


@override_settings(USE_ALLOW_LIST=True)
class IsEmailInAllowListUnitTests(TestCase):
    def test_returns_true_for_active_user_email(self):
        User.objects.create(
            username='active-user@example.com',
            email='active-user@example.com',
            recovery_email='recovery@example.com',
            is_active=True,
        )

        self.assertTrue(is_email_in_allow_list('active-user@example.com'))

    def test_returns_true_for_active_user_recovery_email(self):
        User.objects.create(
            username='active-recovery@example.com',
            email='active-recovery@example.com',
            recovery_email='active-recovery-contact@example.com',
            is_active=True,
        )

        self.assertTrue(is_email_in_allow_list('active-recovery-contact@example.com'))

    def test_returns_true_for_allow_list_entry(self):
        AllowListEntry.objects.create(email='allow-listed@example.com')

        self.assertTrue(is_email_in_allow_list('allow-listed@example.com'))

    def test_returns_false_for_inactive_user_without_allow_list_entry(self):
        User.objects.create(
            username='inactive-user@example.com',
            email='inactive-user@example.com',
            recovery_email='inactive-recovery@example.com',
            is_active=False,
        )

        self.assertFalse(is_email_in_allow_list('inactive-user@example.com'))

    def test_returns_false_when_email_is_missing_from_user_and_allow_list(self):
        self.assertFalse(is_email_in_allow_list('missing@example.com'))

    @override_settings(USE_ALLOW_LIST=False)
    def test_returns_true_when_allow_list_is_disabled(self):
        self.assertTrue(is_email_in_allow_list('not-listed@example.com'))


class DeleteUserDataTestCase(TestCase):
    """Deleting a user must also clean up the external resources behind their custom domains:
    the Stalwart domain, its DKIM signatures, and the hosted DKIM TXT records in Cloudflare."""

    def setUp(self):
        self.user = User.objects.create(
            username=f'test@{settings.PRIMARY_EMAIL_DOMAIN}',
            email='test@example.net',
            oidc_id='delete-user-data-oidc',
        )
        self.account = Account.objects.create(name=self.user.username, user=self.user)
        Email.objects.create(address=self.user.username, type=Email.EmailType.PRIMARY, account=self.account)

        # Patch at the class/task level so these hold wherever MailClient or the task are imported from.
        patchers = {
            'mock_delete_keycloak_user': patch.object(KeycloakClient, 'delete_user'),
            'mock_delete_account': patch.object(MailClient, 'delete_account'),
            'mock_delete_domain': patch.object(MailClient, 'delete_domain'),
            'mock_delete_dkim': patch.object(MailClient, 'delete_dkim'),
            'mock_delete_hosted_dkim_dns_records': patch.object(mail_tasks.delete_hosted_dkim_dns_records, 'delay'),
        }
        for name, patcher in patchers.items():
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def _create_domain(self, name='customdomain.com', status=Domain.DomainStatus.VERIFIED):
        return Domain.objects.create(
            name=name,
            user=self.user,
            stalwart_id='domain-id' if status == Domain.DomainStatus.VERIFIED else None,
            status=status,
        )

    def _delete_user_data(self):
        # Fetch a fresh instance so the cached ``is_migrated`` reflects any settings override.
        return delete_user_data(User.objects.get(pk=self.user.pk))

    def _assert_user_deleted(self):
        self.assertFalse(User.objects.filter(pk=self.user.pk).exists())
        self.assertFalse(Domain.objects.filter(user_id=self.user.pk).exists())

    def test_non_migrated_user_verified_domain_deletes_stalwart_domain_dkim_and_cloudflare_records(self):
        domain = self._create_domain()

        errors = self._delete_user_data()

        self.assertEqual([], errors)
        self.mock_delete_domain.assert_called_once_with(domain.name)
        self.mock_delete_dkim.assert_called_once_with(domain.name)
        self.mock_delete_hosted_dkim_dns_records.assert_called_once_with(domain.name)
        self._assert_user_deleted()

    @override_settings(STALWART_ADMIN_API_USE_JMAP=True)
    def test_migrated_user_verified_domain_deletes_stalwart_domain_and_cloudflare_records(self):
        """The JMAP client's delete_domain also removes the domain's DKIM signatures."""
        domain = self._create_domain()

        errors = self._delete_user_data()

        self.assertEqual([], errors)
        self.mock_delete_domain.assert_called_once_with(domain.name)
        self.mock_delete_hosted_dkim_dns_records.assert_called_once_with(domain.name)
        self._assert_user_deleted()

    @override_settings(STALWART_ADMIN_API_USE_JMAP=True)
    def test_migrated_user_pending_domain_deletes_stalwart_domain_and_cloudflare_records(self):
        """Migrated users get a disabled Stalwart domain as soon as the domain is added, before verification."""
        domain = self._create_domain(status=Domain.DomainStatus.PENDING)

        errors = self._delete_user_data()

        self.assertEqual([], errors)
        self.mock_delete_domain.assert_called_once_with(domain.name)
        self.mock_delete_hosted_dkim_dns_records.assert_called_once_with(domain.name)
        self._assert_user_deleted()

    def test_non_migrated_user_pending_domain_deletes_dkim_and_cloudflare_records(self):
        """DKIM signatures are created and Cloudflare records queued when the domain is added, before verification."""
        domain = self._create_domain(status=Domain.DomainStatus.PENDING)

        errors = self._delete_user_data()

        self.assertEqual([], errors)
        self.mock_delete_dkim.assert_called_once_with(domain.name)
        self.mock_delete_hosted_dkim_dns_records.assert_called_once_with(domain.name)
        self._assert_user_deleted()

    def test_every_custom_domain_is_cleaned_up(self):
        domain_names = {
            self._create_domain('customdomain.com').name,
            self._create_domain('othercustomdomain.com').name,
        }

        errors = self._delete_user_data()

        self.assertEqual([], errors)
        self.assertEqual(domain_names, {c.args[0] for c in self.mock_delete_domain.call_args_list})
        self.assertEqual(domain_names, {c.args[0] for c in self.mock_delete_dkim.call_args_list})
        self.assertEqual(domain_names, {c.args[0] for c in self.mock_delete_hosted_dkim_dns_records.call_args_list})
        self._assert_user_deleted()

    def test_user_without_custom_domains_only_deletes_keycloak_user_and_stalwart_account(self):
        errors = self._delete_user_data()

        self.assertEqual([], errors)
        self.mock_delete_keycloak_user.assert_called_once_with(self.user.oidc_id)
        self.mock_delete_account.assert_called_once_with(self.user.username)
        self.mock_delete_domain.assert_not_called()
        self.mock_delete_dkim.assert_not_called()
        self.mock_delete_hosted_dkim_dns_records.assert_not_called()
        self._assert_user_deleted()

    def test_shared_domains_are_never_cleaned_up(self):
        """Shared domains have Stalwart domains and DKIM signatures used by every user."""
        for shared_domain in settings.ALLOWED_EMAIL_DOMAINS[1:]:
            Email.objects.create(
                address=f'test@{shared_domain}',
                type=Email.EmailType.ALIAS,
                account=self.account,
            )
        domain = self._create_domain()

        self._delete_user_data()

        cleanup_mocks = [self.mock_delete_domain, self.mock_delete_dkim, self.mock_delete_hosted_dkim_dns_records]
        for cleanup_mock in cleanup_mocks:
            cleaned_up = {c.args[0] for c in cleanup_mock.call_args_list}
            self.assertEqual({domain.name}, cleaned_up)
            self.assertFalse(cleaned_up & set(settings.ALLOWED_EMAIL_DOMAINS))

    def test_domains_are_cleaned_up_before_local_rows_are_deleted(self):
        domain = self._create_domain()
        domain_existed_during_cleanup = []
        self.mock_delete_domain.side_effect = lambda name: domain_existed_during_cleanup.append(
            Domain.objects.filter(name=name).exists()
        )

        self._delete_user_data()

        self.assertEqual([True], domain_existed_during_cleanup)
        self.assertFalse(Domain.objects.filter(name=domain.name).exists())

    def test_domain_cleanup_does_not_depend_on_stalwart_account(self):
        self.account.delete()
        domain = self._create_domain()

        errors = self._delete_user_data()

        self.assertEqual([], errors)
        self.mock_delete_account.assert_not_called()
        self.mock_delete_domain.assert_called_once_with(domain.name)
        self.mock_delete_dkim.assert_called_once_with(domain.name)
        self.mock_delete_hosted_dkim_dns_records.assert_called_once_with(domain.name)
        self._assert_user_deleted()

    def test_domain_already_missing_from_stalwart_is_not_an_error(self):
        domain = self._create_domain()
        self.mock_delete_domain.side_effect = DomainNotFoundError(domain.name)

        errors = self._delete_user_data()

        self.assertEqual([], errors)
        self.mock_delete_dkim.assert_called_once_with(domain.name)
        self.mock_delete_hosted_dkim_dns_records.assert_called_once_with(domain.name)
        self._assert_user_deleted()

    def test_stalwart_domain_failure_is_reported_and_other_cleanup_continues(self):
        failing_domain = self._create_domain('customdomain.com')
        other_domain = self._create_domain('othercustomdomain.com')

        def delete_domain(name):
            if name == failing_domain.name:
                raise RuntimeError('stalwart unavailable')

        self.mock_delete_domain.side_effect = delete_domain

        with self.assertLogs(level='ERROR'):
            errors = self._delete_user_data()

        self.assertEqual(1, len(errors))
        self.assertIn(failing_domain.name, errors[0])
        self.assertIn(call(other_domain.name), self.mock_delete_domain.call_args_list)
        self.assertIn(call(other_domain.name), self.mock_delete_hosted_dkim_dns_records.call_args_list)
        self.mock_delete_keycloak_user.assert_called_once_with(self.user.oidc_id)
        self.mock_delete_account.assert_called_once_with(self.user.username)
        self._assert_user_deleted()

    def test_cloudflare_queue_failure_is_reported_and_other_cleanup_continues(self):
        failing_domain = self._create_domain('customdomain.com')
        other_domain = self._create_domain('othercustomdomain.com')

        def queue_delete(name):
            if name == failing_domain.name:
                raise RuntimeError('broker unavailable')

        self.mock_delete_hosted_dkim_dns_records.side_effect = queue_delete

        with self.assertLogs(level='ERROR'):
            errors = self._delete_user_data()

        self.assertEqual(1, len(errors))
        self.assertIn(failing_domain.name, errors[0])
        self.assertIn(call(other_domain.name), self.mock_delete_domain.call_args_list)
        self.assertIn(call(other_domain.name), self.mock_delete_hosted_dkim_dns_records.call_args_list)
        self.mock_delete_keycloak_user.assert_called_once_with(self.user.oidc_id)
        self.mock_delete_account.assert_called_once_with(self.user.username)
        self._assert_user_deleted()

    def test_keycloak_failure_does_not_skip_domain_cleanup(self):
        domain = self._create_domain()
        self.mock_delete_keycloak_user.side_effect = DeleteUserError(error='boom', oidc_id=self.user.oidc_id)

        with self.assertLogs(level='ERROR'):
            errors = self._delete_user_data()

        self.assertEqual(1, len(errors))
        self.mock_delete_domain.assert_called_once_with(domain.name)
        self.mock_delete_hosted_dkim_dns_records.assert_called_once_with(domain.name)
        self._assert_user_deleted()
