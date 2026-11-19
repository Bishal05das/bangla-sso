from django.contrib import admin
from oauth2_provider.admin import ApplicationAdmin
from oauth2_provider.models import get_application_model

from .models import BackchannelLogoutDelivery, ClientLogoutConfig

Application = get_application_model()


class ClientLogoutConfigInline(admin.StackedInline):
    model = ClientLogoutConfig
    can_delete = True
    max_num = 1


# Re-register DOT's Application admin with our logout settings shown inline.
admin.site.unregister(Application)


@admin.register(Application)
class ApplicationWithLogoutAdmin(ApplicationAdmin):
    inlines = [ClientLogoutConfigInline]


@admin.register(BackchannelLogoutDelivery)
class BackchannelLogoutDeliveryAdmin(admin.ModelAdmin):
    list_display = ("application", "subject", "status", "attempts", "next_attempt_at", "delivered_at")
    list_filter = ("status", "application")
    search_fields = ("subject",)
    readonly_fields = [f.name for f in BackchannelLogoutDelivery._meta.fields]

    def has_add_permission(self, request):
        return False
