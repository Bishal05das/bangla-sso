import time

from django.core.management.base import BaseCommand

from clients.backchannel import deliver_pending


class Command(BaseCommand):
    help = "Deliver queued OIDC back-channel logout notifications to client apps."

    def add_arguments(self, parser):
        parser.add_argument("--loop", action="store_true", help="Keep running (worker mode).")
        parser.add_argument("--interval", type=float, default=2.0, help="Seconds between polls.")

    def handle(self, *args, loop, interval, **options):
        while True:
            sent = deliver_pending()
            if sent:
                self.stdout.write(f"Delivered {sent} logout notification(s).")
            if not loop:
                return
            time.sleep(interval)
