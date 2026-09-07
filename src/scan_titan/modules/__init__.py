"""Scan Titan async module registry."""

from .advanced_logic import AdvancedLogicModule
from .api_dast import ApiDastModule
from .api_spa import ApiSpaModule
from .auth_session import AuthSessionModule
from .authorization import AuthorizationModule
from .browser_audit import BrowserAuditModule
from .client_side import ClientSideModule
from .cors import CorsModule
from .crypto_tls import CryptoTlsModule
from .headers import HeadersModule
from .infra_network import InfraNetworkModule
from .injection import InjectionModule
from .lfi import LfiModule
from .paths import PathDiscoveryModule
from .recon_surface import ReconSurfaceModule
from .site_map import SiteMapModule
from .unauthenticated_map import UnauthenticatedMapModule
from .sqli import SqliModule
from .ssrf import SsrfModule
from .waf_resilience import WafResilienceModule
from .xss import XssModule

DEFAULT_MODULES = [
    ReconSurfaceModule,
    ApiSpaModule,
    ApiDastModule,
    SiteMapModule,
    UnauthenticatedMapModule,
    PathDiscoveryModule,
    HeadersModule,
    InfraNetworkModule,
    CryptoTlsModule,
    AuthSessionModule,
    AuthorizationModule,
    SqliModule,
    LfiModule,
    SsrfModule,
    InjectionModule,
    XssModule,
    CorsModule,
    WafResilienceModule,
    ClientSideModule,
    BrowserAuditModule,
    AdvancedLogicModule,
]
