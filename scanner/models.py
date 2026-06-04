# scanner/models.py
# =============================================================================
#  MIAT — Unified Models File
#
#  ONE file. No more models_dga_addition.py or models_exfil_addition.py.
#  All models live here. Django loads them all at startup automatically.
#
#  Model hierarchy:
#    Agent          → registered agent instances
#    ScanRequest    → one nmap scan job
#    HostResult     → one host found during a scan
#    PortFinding    → one open port on a host
#    DGAResult      → one DGA test run
#    ExfilResult    → one exfiltration simulation run
# =============================================================================

import hashlib
import secrets
import hmac

from django.db             import models
from django.contrib.auth.models import User
from django.utils          import timezone


# =============================================================================
# CHOICES
# =============================================================================

class ScanStatus(models.TextChoices):
    PENDING  = 'pending',  'Pending'
    RUNNING  = 'running',  'Running'
    COMPLETE = 'complete', 'Complete'
    FAILED   = 'failed',   'Failed'
    CACHED   = 'cached',   'Cached'


class ScanProfile(models.TextChoices):
    FAST    = 'fast',    'Fast (top 100 ports)'
    DEFAULT = 'default', 'Default (top 1000 ports)'
    DEEP    = 'deep',    'Deep (all ports + OS)'
    PING    = 'ping',    'Ping sweep'


class Severity(models.TextChoices):
    HIGH   = 'HIGH',   'High'
    MEDIUM = 'MEDIUM', 'Medium'
    LOW    = 'LOW',    'Low'
    INFO   = 'INFO',   'Info'
    NONE   = 'NONE',   'None'


class DGAAlgorithm(models.TextChoices):
    DATE_SEED = 'date_seed', 'Date-Seeded SHA-256'
    XOR_LCG   = 'xor_lcg',  'XOR + LCG (Conficker-style)'
    WORDLIST  = 'wordlist',  'Wordlist Combination'


class ExfilTechnique(models.TextChoices):
    DNS  = 'dns',  'DNS Tunnelling'
    HTTP = 'http', 'HTTP Header Injection'
    ICMP = 'icmp', 'ICMP Payload Stuffing'


class ExfilProfile(models.TextChoices):
    BURST     = 'burst',     'Burst'
    SLOW_DRIP = 'slow_drip', 'Slow Drip'
    JITTER    = 'jitter',    'Jitter'


# =============================================================================
# MODEL 1: AGENT
# Represents one registered endpoint agent.
# =============================================================================

class Agent(models.Model):
    """
    WHY THIS EXISTS:
    Every machine running orchestrator.py must register here first.
    Registration gives the agent a unique identity (agent_id) and
    credentials (auth_token + secret_key). Every API request from
    the agent is verified against these — proving which machine
    sent the data and that the body was not tampered with.
    Without this, any script could post fake scan results.
    """

    agent_id   = models.CharField(max_length=64, unique=True, db_index=True)
    name       = models.CharField(max_length=128, blank=True)
    is_active  = models.BooleanField(default=True)

    # Credentials
    auth_token = models.CharField(max_length=64, unique=True, db_index=True)
    secret_key = models.CharField(max_length=64)

    # Capabilities — updated when agent connects and reports loaded plugins
    capabilities = models.JSONField(default=list, blank=True)

    # Tracking
    registered_by  = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='registered_agents',
    )
    registered_at  = models.DateTimeField(auto_now_add=True)
    last_seen_at   = models.DateTimeField(null=True, blank=True)
    last_seen_ip   = models.GenericIPAddressField(null=True, blank=True)
    total_requests = models.PositiveIntegerField(default=0)

    @staticmethod
    def generate_auth_token() -> str:
        return secrets.token_hex(32)

    @staticmethod
    def generate_secret_key() -> str:
        return secrets.token_hex(32)

    def verify_hmac(self, signature: str, timestamp: str, body: str) -> bool:
        expected = hmac.new(
            self.secret_key.encode('utf-8'),
            f"{timestamp}:{body}".encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    def mark_seen(self, ip_address: str = None) -> None:
        self.last_seen_at   = timezone.now()
        self.total_requests += 1
        if ip_address:
            self.last_seen_ip = ip_address
        self.save(update_fields=['last_seen_at', 'last_seen_ip', 'total_requests'])

    @property
    def is_online(self) -> bool:
        if not self.last_seen_at:
            return False
        return (timezone.now() - self.last_seen_at).seconds < 90

    def __str__(self):
        return f"Agent '{self.agent_id}' [{'active' if self.is_active else 'disabled'}]"

    class Meta:
        ordering            = ['-registered_at']
        verbose_name        = 'Agent'
        verbose_name_plural = 'Agents'


# =============================================================================
# MODEL 2: SCAN REQUEST
# One nmap scan job submitted by user or agent.
# =============================================================================

class ScanRequest(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='scan_requests',
    )
    agent = models.ForeignKey(
        Agent, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='scan_requests',
    )
    target       = models.CharField(max_length=255)
    scan_profile = models.CharField(
        max_length=20, choices=ScanProfile.choices, default=ScanProfile.DEFAULT,
    )
    token     = models.CharField(max_length=64, db_index=True, editable=False)
    status    = models.CharField(
        max_length=20, choices=ScanStatus.choices, default=ScanStatus.PENDING,
    )
    cache_hit   = models.BooleanField(default=False)
    cached_from = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True,
    )

    # Risk summary
    overall_risk          = models.CharField(max_length=10, choices=Severity.choices, default=Severity.NONE, blank=True)
    total_hosts           = models.IntegerField(default=0)
    hosts_up              = models.IntegerField(default=0)
    total_open_ports      = models.IntegerField(default=0)
    high_severity_count   = models.IntegerField(default=0)
    medium_severity_count = models.IntegerField(default=0)
    error_message         = models.TextField(blank=True, default='')

    created_at   = models.DateTimeField(auto_now_add=True)
    started_at   = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    @property
    def duration_seconds(self):
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).seconds
        return None

    @staticmethod
    def generate_token(target: str, scan_profile: str) -> str:
        raw = f"{target.strip().lower()}:{scan_profile}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = self.generate_token(self.target, self.scan_profile)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Scan #{self.pk} — {self.target} [{self.status}]"

    class Meta:
        ordering = ['-created_at']


# =============================================================================
# MODEL 3: HOST RESULT
# One host discovered during a scan.
# =============================================================================

class HostResult(models.Model):
    scan        = models.ForeignKey(ScanRequest, on_delete=models.CASCADE, related_name='hosts')
    ip_address  = models.GenericIPAddressField()
    hostname    = models.CharField(max_length=255, blank=True, default='')
    status      = models.CharField(max_length=20, default='unknown')
    os_detected = models.CharField(max_length=255, blank=True, default='N/A')
    os_accuracy = models.IntegerField(default=0)
    host_risk   = models.CharField(max_length=10, choices=Severity.choices, default=Severity.NONE)
    open_port_count = models.IntegerField(default=0)
    scanned_at  = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} [{self.host_risk}]"

    class Meta:
        ordering       = ['ip_address']
        unique_together = [('scan', 'ip_address')]


# =============================================================================
# MODEL 4: PORT FINDING
# One open port found on a host.
# =============================================================================

class PortFinding(models.Model):
    host            = models.ForeignKey(HostResult, on_delete=models.CASCADE, related_name='ports')
    port            = models.IntegerField()
    protocol        = models.CharField(max_length=10)
    state           = models.CharField(max_length=20)
    service_name    = models.CharField(max_length=100, blank=True, default='')
    service_product = models.CharField(max_length=255, blank=True, default='')
    service_version = models.CharField(max_length=255, blank=True, default='')
    service_cpe     = models.CharField(max_length=255, blank=True, default='')
    severity        = models.CharField(max_length=10, choices=Severity.choices, default=Severity.INFO)
    risk_note       = models.TextField(blank=True, default='')
    is_critical_alert = models.BooleanField(default=False)
    alert_message   = models.CharField(max_length=500, blank=True, default='')
    found_at        = models.DateTimeField(auto_now_add=True)

    @property
    def full_version(self):
        parts = [self.service_product, self.service_version]
        return ' '.join(p for p in parts if p).strip() or 'N/A'

    def __str__(self):
        return f"Port {self.port}/{self.protocol} [{self.state}] {self.service_name} — {self.severity}"

    class Meta:
        ordering        = ['port']
        unique_together = [('host', 'port', 'protocol')]


# =============================================================================
# MODEL 5: DGA RESULT
# One complete DGA test run.
# =============================================================================

class DGAResult(models.Model):
    agent     = models.ForeignKey(
        Agent, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='dga_results',
    )
    algorithm       = models.CharField(max_length=20, choices=DGAAlgorithm.choices, default=DGAAlgorithm.DATE_SEED)
    total_queries   = models.IntegerField(default=0)
    rate_per_sec    = models.FloatField(default=1.0)
    dns_server      = models.CharField(max_length=64, blank=True, default='system')
    seed_date       = models.DateField(null=True, blank=True)
    nxdomain_count  = models.IntegerField(default=0)
    resolved_count  = models.IntegerField(default=0)
    timeout_count   = models.IntegerField(default=0)
    error_count     = models.IntegerField(default=0)
    nxdomain_ratio  = models.FloatField(default=0.0)
    avg_entropy     = models.FloatField(default=0.0)
    max_entropy     = models.FloatField(default=0.0)
    min_entropy     = models.FloatField(default=0.0)
    duration_sec    = models.FloatField(default=0.0)
    ids_detected    = models.BooleanField(null=True, blank=True)
    ids_detection_notes = models.TextField(blank=True, default='')
    domains_json    = models.JSONField(default=list)
    created_at      = models.DateTimeField(auto_now_add=True)

    @property
    def risk_level(self) -> str:
        if self.nxdomain_ratio >= 0.8:
            return 'HIGH'
        elif self.nxdomain_ratio >= 0.5:
            return 'MEDIUM'
        return 'LOW'

    @property
    def ids_status(self) -> str:
        if self.ids_detected is None:
            return 'Unknown'
        return 'Detected' if self.ids_detected else 'Evaded'

    def __str__(self):
        return f"DGA [{self.algorithm}] {self.nxdomain_count}/{self.total_queries} NXDOMAIN"

    class Meta:
        ordering            = ['-created_at']
        verbose_name        = 'DGA Result'
        verbose_name_plural = 'DGA Results'


# =============================================================================
# MODEL 6: EXFIL RESULT
# One complete exfiltration simulation run.
# =============================================================================

class ExfilResult(models.Model):
    agent     = models.ForeignKey(
        Agent, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='exfil_results',
    )
    technique        = models.CharField(max_length=10, choices=ExfilTechnique.choices, default=ExfilTechnique.DNS)
    profile          = models.CharField(max_length=20, choices=ExfilProfile.choices, default=ExfilProfile.BURST)
    target           = models.CharField(max_length=255, blank=True)
    total_chunks     = models.IntegerField(default=0)
    successful       = models.IntegerField(default=0)
    errors           = models.IntegerField(default=0)
    duration_sec     = models.FloatField(default=0.0)
    avg_interval_sec = models.FloatField(default=0.0)
    ids_severity     = models.CharField(max_length=20, blank=True)
    ids_signatures   = models.JSONField(default=list)
    ids_detected     = models.BooleanField(null=True, blank=True)
    ids_detection_notes = models.TextField(blank=True, default='')
    packets_json     = models.JSONField(default=list)
    created_at       = models.DateTimeField(auto_now_add=True)

    @property
    def success_rate(self) -> float:
        if self.total_chunks == 0:
            return 0.0
        return round(self.successful / self.total_chunks, 4)

    @property
    def ids_status(self) -> str:
        if self.ids_detected is None:
            return 'Unknown'
        return 'Detected' if self.ids_detected else 'Evaded'

    def __str__(self):
        return f"Exfil [{self.technique}/{self.profile}] {self.successful}/{self.total_chunks} sent"

    class Meta:
        ordering            = ['-created_at']
        verbose_name        = 'Exfil Result'
        verbose_name_plural = 'Exfil Results'