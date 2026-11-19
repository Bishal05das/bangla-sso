from django.core.management.base import BaseCommand, CommandError
from oauth2_provider.models import get_application_model

from clients.models import ClientLogoutConfig


class Command(BaseCommand):
    help = "Set the back-channel logout URI for a client application."

    def add_arguments(self, parser):
        parser.add_argument("client_id")
        parser.add_argument("uri")

    def handle(self, *args, client_id, uri, **options):
        try:
            application = get_application_model().objects.get(client_id=client_id)
        except get_application_model().DoesNotExist:
            raise CommandError(f"No application with client_id {client_id!r}.")
        config = ClientLogoutConfig(application=application, backchannel_logout_uri=uri)
        config.full_clean(exclude=["application"])
        ClientLogoutConfig.objects.update_or_create(
            application=application, defaults={"backchannel_logout_uri": uri}
        )
        self.stdout.write(self.style.SUCCESS(f"{application.name}: back-channel logout -> {uri}"))
