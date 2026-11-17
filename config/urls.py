"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path, re_path
from oauth2_provider import views as oauth2_views

# Only the endpoints an OIDC provider needs. django-oauth-toolkit's default
# urls.py also exposes self-service app registration pages, which would let ANY
# logged-in user create OAuth clients. Clients are managed by admins only.
oauth2_urlpatterns = [
    path("authorize/", oauth2_views.AuthorizationView.as_view(), name="authorize"),
    path("token/", oauth2_views.TokenView.as_view(), name="token"),
    path("revoke_token/", oauth2_views.RevokeTokenView.as_view(), name="revoke-token"),
    re_path(
        r"^\.well-known/openid-configuration/?$",
        oauth2_views.ConnectDiscoveryInfoView.as_view(),
        name="oidc-connect-discovery-info",
    ),
    path(".well-known/jwks.json", oauth2_views.JwksInfoView.as_view(), name="jwks-info"),
    path("userinfo/", oauth2_views.UserInfoView.as_view(), name="user-info"),
]

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/", include("accounts.urls")),
    path("o/", include((oauth2_urlpatterns, "oauth2_provider"))),
]

