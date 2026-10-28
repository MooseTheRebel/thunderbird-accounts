import logging

import sentry_sdk

from thunderbird_accounts.mail import tasks as mail_tasks
from thunderbird_accounts.mail.clients import MailClient
from thunderbird_accounts.mail.exceptions import DomainNotFoundError
from thunderbird_accounts.mail.models import Domain


def capture_custom_domain_exception(exception: Exception, domain: Domain, *, phase: str):
    sentry_sdk.set_context(
        'domain',
        {
            'phase': phase,
            'domain_name': domain.name,
            'domain_status': domain.status,
        },
    )
    sentry_sdk.capture_exception(exception)


def delete_custom_domain_resources(domain: Domain, stalwart_client=None) -> list[str]:
    stalwart_client = stalwart_client or MailClient()
    errors = []

    try:
        stalwart_client.delete_domain(domain.name)
    except DomainNotFoundError:
        # While it's not in Stalwart we seem to have a local reference,
        # so try deleting dkim and then local ref
        logging.info(f'[delete_custom_domain_resources] Stalwart domain {domain.name} is already removed')
    except Exception as ex:
        capture_custom_domain_exception(ex, domain, phase='delete_stalwart_domain')
        errors.append(f'Stalwart domain {domain.name}: {ex}')

    # The v0.16 delete_domain removes the domain's signatures itself; the legacy one does not.
    if not domain.user.is_migrated:
        try:
            stalwart_client.delete_dkim(domain.name)
        except Exception as ex:
            capture_custom_domain_exception(ex, domain, phase='delete_dkim')
            errors.append(f'Stalwart DKIM {domain.name}: {ex}')

    # Hosted records are published at creation for every user type, so they are removed for every one.
    try:
        mail_tasks.delete_hosted_dkim_dns_records.delay(domain.name)
    except Exception as ex:
        capture_custom_domain_exception(ex, domain, phase='delete_hosted_dkim_dns_records')
        errors.append(f'Cloudflare {domain.name}: {ex}')

    return errors
