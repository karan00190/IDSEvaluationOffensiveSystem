# scanner/models.py
# ─────────────────────────────────────────────────────────────────────────────
#  MIAT — Malware Impact Assessment Tool
#  models.py defines the DATABASE SCHEMA.
#
#  Django ORM rule: one Python class = one database table.
#  You never write SQL — Django generates it from these classes.
#
#  Our 3 models and what they represent:
#    ScanRequest  →  one scan job submitted by a user
#    HostResult   →  one host found during that scan (can be many per scan)
#    PortFinding  →  one open port found on a host (can be many per host)
#
#  Relationship:
#    ScanRequest (1) ──► HostResult (many) ──► PortFinding (many)
#
#  Example in plain English:
#    "User scanned 192.168.1.0/24"  →  ScanRequest
#      "Found host 192.168.1.1"     →  HostResult
#        "Port 22 open (SSH)"       →  PortFinding
#        "Port 80 open (HTTP)"      →  PortFinding
#      "Found host 192.168.1.5"     →  HostResult
#        "Port 3306 open (MySQL)"   →  PortFinding
# ─────────────────────────────────────────────────────────────────────────────

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import hashlib
import hmac
import secrets



# ─────────────────────────────────────────────────────────────────────────────
# CHOICES
# Django pattern: define fixed options as tuples (stored_value, display_label)
# Using choices prevents garbage data in the DB and gives you dropdowns in admin.
# ─────────────────────────────────────────────────────────────────────────────

class ScanStatus(models.TextChoices):
    # TextChoices means values are stored as strings in the DB
    PENDING    = 'pending',    'Pending'       # job created, not started yet
    RUNNING    = 'running',    'Running'       # nmap is actively scanning
    COMPLETE   = 'complete',   'Complete'      # finished successfully
    FAILED     = 'failed',     'Failed'        # nmap errored out
    CACHED     = 'cached',     'Cached'        # returned from cache, nmap skipped


class ScanProfile(models.TextChoices):
    FAST    = 'fast',    'Fast (top 100 ports)'
    DEFAULT = 'default', 'Default (top 1000 ports)'
    DEEP    = 'deep',    'Deep (all ports + OS detection)'
    PING    = 'ping',    'Ping sweep (hosts only)'


class Severity(models.TextChoices):
    HIGH   = 'HIGH',   'High'
    MEDIUM = 'MEDIUM', 'Medium'
    LOW    = 'LOW',    'Low'
    INFO   = 'INFO',   'Info'
    NONE   = 'NONE',   'None'


# ─────────────────────────────────────────────────────────────────────────────
# MODEL 1: ScanRequest
# Represents one scan job — submitted by a user against one target.
# This is the "parent" record everything else links back to.
# ─────────────────────────────────────────────────────────────────────────────

class ScanRequest(models.Model):

    # ── Who submitted it ────────────────────────────────────────────────────
    # ForeignKey = many scans can belong to one user
    # on_delete=CASCADE means if the user is deleted, their scans are deleted too
    # on_delete=SET_NULL would keep the scan but set user to null — useful for audit logs
    # null=True, blank=True makes the field optional (anonymous scans allowed)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='scan_requests',
        # related_name lets you do: user.scan_requests.all() from a User object
    )

    # ── What to scan ────────────────────────────────────────────────────────
    # CharField = string field with a max length
    target = models.CharField(
        max_length=255,
        help_text='IP address, hostname, or CIDR range e.g. 192.168.1.0/24'
    )

    # choices=ScanProfile.choices restricts values to the defined options
    scan_profile = models.CharField(
        max_length=20,
        choices=ScanProfile.choices,
        default=ScanProfile.DEFAULT,
    )

    # ── Token — the caching key ──────────────────────────────────────────────
    # SHA-256 hash of (target + scan_profile).
    # Same target + same profile = same token = return cached result.
    # db_index=True creates a DB index for fast lookups on this field.
    # unique=False because we want multiple historical records with the same token.
    token = models.CharField(
        max_length=64,
        db_index=True,
        editable=False,  # never edited manually — always generated
    )

    # ── Status ───────────────────────────────────────────────────────────────
    status = models.CharField(
        max_length=20,
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
    )

    # ── Cache tracking ───────────────────────────────────────────────────────
    # Was this result served from cache (nmap skipped)?
    cache_hit = models.BooleanField(default=False)

    # If cache_hit=True, which earlier scan did we reuse?
    # null=True because most scans are NOT cache hits
    cached_from = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='cache_copies',
    )

    # ── Risk summary ─────────────────────────────────────────────────────────
    # Stored here so the dashboard can show risk without joining 3 tables
    overall_risk = models.CharField(
        max_length=10,
        choices=Severity.choices,
        default=Severity.NONE,
        blank=True,
    )

    total_hosts   = models.IntegerField(default=0)
    hosts_up      = models.IntegerField(default=0)
    total_open_ports = models.IntegerField(default=0)
    high_severity_count   = models.IntegerField(default=0)
    medium_severity_count = models.IntegerField(default=0)

    # ── Error info ───────────────────────────────────────────────────────────
    # If the scan fails, store why
    error_message = models.TextField(blank=True, default='')

    # ── Timestamps ───────────────────────────────────────────────────────────
    # auto_now_add=True: set automatically when record is first created, never changed
    # auto_now=True: updated every time .save() is called
    created_at   = models.DateTimeField(auto_now_add=True)
    started_at   = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # ── Duration property ────────────────────────────────────────────────────
    # @property means you call it like scan.duration, not scan.duration()
    # It's computed, not stored — always fresh
    @property
    def duration_seconds(self):
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).seconds
        return None

    # ── Token generation ─────────────────────────────────────────────────────
    @staticmethod
    def generate_token(target: str, scan_profile: str) -> str:
        """
        Generate a deterministic SHA-256 token from target + scan_profile.
        Same inputs always produce the same token — that's the cache key.
        """
        raw = f"{target.strip().lower()}:{scan_profile}"
        return hashlib.sha256(raw.encode()).hexdigest()

    # ── Override save() ──────────────────────────────────────────────────────
    # Called every time scan.save() runs — auto-generates the token
    def save(self, *args, **kwargs):
        if not self.token:
            self.token = self.generate_token(self.target, self.scan_profile)
        super().save(*args, **kwargs)

    # ── String representation ────────────────────────────────────────────────
    # What shows in Django admin and in print() calls
    def __str__(self):
        return f"Scan #{self.pk} — {self.target} [{self.status}]"

    # ── Meta ─────────────────────────────────────────────────────────────────
    class Meta:
        ordering = ['-created_at']  # newest first by default
        verbose_name = 'Scan Request'
        verbose_name_plural = 'Scan Requests'


# ─────────────────────────────────────────────────────────────────────────────
# MODEL 2: HostResult
# One record per host discovered during a scan.
# A subnet scan of /24 might produce 10 HostResult records.
# ─────────────────────────────────────────────────────────────────────────────

class HostResult(models.Model):

    # ── Link back to the scan ────────────────────────────────────────────────
    # on_delete=CASCADE: if the ScanRequest is deleted, delete this host too
    # related_name='hosts' lets you do: scan.hosts.all()
    scan = models.ForeignKey(
        ScanRequest,
        on_delete=models.CASCADE,
        related_name='hosts',
    )

    # ── Host identity ────────────────────────────────────────────────────────
    ip_address = models.GenericIPAddressField()
    # GenericIPAddressField validates both IPv4 and IPv6

    hostname = models.CharField(max_length=255, blank=True, default='')
    # blank=True means the field is optional in forms and can be empty string

    # ── Host state ───────────────────────────────────────────────────────────
    status = models.CharField(
        max_length=20,
        default='unknown',
        # 'up', 'down', 'unknown'
    )

    # ── OS detection ─────────────────────────────────────────────────────────
    os_detected  = models.CharField(max_length=255, blank=True, default='N/A')
    os_accuracy  = models.IntegerField(default=0)  # percentage 0–100

    # ── Risk rollup ──────────────────────────────────────────────────────────
    # Worst severity found across all ports on this host
    host_risk = models.CharField(
        max_length=10,
        choices=Severity.choices,
        default=Severity.NONE,
    )

    open_port_count = models.IntegerField(default=0)

    # ── Timestamps ───────────────────────────────────────────────────────────
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        label = self.hostname if self.hostname else self.ip_address
        return f"{label} [{self.host_risk}]"

    class Meta:
        ordering = ['ip_address']
        verbose_name = 'Host Result'
        verbose_name_plural = 'Host Results'
        # unique_together prevents saving the same IP twice for the same scan
        unique_together = [('scan', 'ip_address')]


# ─────────────────────────────────────────────────────────────────────────────
# MODEL 3: PortFinding
# One record per open port found on a host.
# A host with 5 open ports → 5 PortFinding records.
# ─────────────────────────────────────────────────────────────────────────────

class PortFinding(models.Model):

    # ── Link back to the host ────────────────────────────────────────────────
    host = models.ForeignKey(
        HostResult,
        on_delete=models.CASCADE,
        related_name='ports',
        # related_name='ports' lets you do: host.ports.all()
    )

    # ── Port info ────────────────────────────────────────────────────────────
    port     = models.IntegerField()            # 0–65535
    protocol = models.CharField(max_length=10)  # 'tcp' or 'udp'
    state    = models.CharField(max_length=20)  # 'open', 'closed', 'filtered'

    # ── Service info ─────────────────────────────────────────────────────────
    service_name    = models.CharField(max_length=100, blank=True, default='')
    service_product = models.CharField(max_length=255, blank=True, default='')
    service_version = models.CharField(max_length=255, blank=True, default='')
    service_cpe     = models.CharField(max_length=255, blank=True, default='')
    # CPE = Common Platform Enumeration — standard identifier like cpe:/a:apache:http_server:2.4

    # ── Risk assessment ──────────────────────────────────────────────────────
    severity = models.CharField(
        max_length=10,
        choices=Severity.choices,
        default=Severity.INFO,
    )
    risk_note = models.TextField(blank=True, default='')

    # ── Critical alert flag ──────────────────────────────────────────────────
    # True if this port triggered a specific security rule
    # (e.g. FTP on 21, Telnet on 23, DB on 3306)
    is_critical_alert = models.BooleanField(default=False)
    alert_message     = models.CharField(max_length=500, blank=True, default='')

    # ── Timestamp ────────────────────────────────────────────────────────────
    found_at = models.DateTimeField(auto_now_add=True)

    # ── Helper property ──────────────────────────────────────────────────────
    @property
    def full_version(self):
        """Returns 'Apache httpd 2.4.41' style string."""
        parts = [self.service_product, self.service_version]
        return ' '.join(p for p in parts if p).strip() or 'N/A'

    def __str__(self):
        return (
            f"Port {self.port}/{self.protocol} "
            f"[{self.state}] {self.service_name} — {self.severity}"
        )

    class Meta:
        ordering = ['port']
        verbose_name = 'Port Finding'
        verbose_name_plural = 'Port Findings'
        unique_together = [('host', 'port', 'protocol')]


class Agent(models.Model):
    agent_id = models.CharField(
        max_length= 64,
        unique = True,
        db_index = True,
        help_text = 'Unique identifier for this agent, e.g. barc-lab-01'
    )

    name = models.CharField(max_length= 128, blank = True)

    auth_token = models.CharField(max_length=64, unique = True, db_index = True)

    secret_key = models.CharField(max_length=64)

    is_active = models.BooleanField(default = True)

    registered_by  = models.ForeignKey(
        User,
        on_delete= models.SET_NULL,
        null = True, blank= True,
        related_name = 'registered_agents',
    )

    registered_at = models.DateTimeField(auto_now_add = True)
    last_seen_at = models.DateTimeField(null = True, blank = True)
    last_seen_ip = models.GenericIPAddressField(null = True, blank = True)
    total_requests = models.PositiveIntegerField(default = 0)

    @property
    def is_authenticated(self):
        """
        Required by Django REST Framework permissions. 
        Always returns True for a valid Agent.
        """
        return True
    
    #Token generation helpers 

    @staticmethod
    def generate_auth_token() -> str:
        """Generate a cryptographically secure 32-byte hex token."""
        return secrets.token_hex(32)   # 64 character hex string
 
    @staticmethod
    def generate_secret_key() -> str:
        """Generate a cryptographically secure 32-byte secret key."""
        return secrets.token_hex(32)
 
    # ── HMAC verification ─────────────────────────────────────────────────────
 
    def verify_hmac_signature(self, signature: str, timestamp: str, body: str) -> bool:
        """
        Verify the HMAC-SHA256 signature sent by the agent.
 
        The agent computes:
            message = timestamp + ":" + body
            signature = HMAC-SHA256(secret_key, message)
 
        The server recomputes the same signature and compares.
        Using hmac.compare_digest() prevents timing attacks.
        """
        message = f"{timestamp}:{body}".encode('utf-8')
        expected = hmac.new(
            self.secret_key.encode('utf-8'),
            message,
            hashlib.sha256
        ).hexdigest()
        # compare_digest is safe against timing attacks
        return hmac.compare_digest(expected, signature)
 
    def mark_seen(self, ip_address: str = None) -> None:
        """Update last_seen_at and total_requests. Called on every authenticated request."""
        self.last_seen_at   = timezone.now()
        self.total_requests += 1
        if ip_address:
            self.last_seen_ip = ip_address
        self.save(update_fields=['last_seen_at', 'last_seen_ip', 'total_requests'])
 
    def __str__(self):
        status = 'active' if self.is_active else 'inactive'
        return f"Agent '{self.agent_id}' [{status}]"
 
    class Meta:
        ordering = ['-registered_at']
        verbose_name = 'Agent'
        verbose_name_plural = 'Agents'
    

    # scanner/models.py — ADD THIS at the bottom of your existing models.py
# Do NOT replace models.py — paste from here to the end of the file.

# =============================================================================
# DGA RESULT MODEL
# Stores each DGA test run's summary and per-domain findings.
# =============================================================================

class DGAAlgorithm(models.TextChoices):
    DATE_SEED = 'date_seed', 'Date-Seeded SHA-256'
    XOR_LCG   = 'xor_lcg',  'XOR + LCG (Conficker-style)'
    WORDLIST  = 'wordlist',  'Wordlist Combination'


class DGAResult(models.Model):
    """
    Stores the result of one complete DGA test run.
    One record per run — contains summary stats + all domain findings as JSON.

    Relationship to Agent:
        Each DGA run is submitted by one agent.
        agent FK → so we know which endpoint ran the test.
    """

    # ── Who ran this test ─────────────────────────────────────────────────────
    agent = models.ForeignKey(
        'Agent',
        on_delete    = models.SET_NULL,
        null         = True,
        blank        = True,
        related_name = 'dga_results',
    )

    # ── Test configuration ────────────────────────────────────────────────────
    algorithm   = models.CharField(
        max_length = 20,
        choices    = DGAAlgorithm.choices,
        default    = DGAAlgorithm.DATE_SEED,
    )
    total_queries = models.IntegerField(default=0)
    rate_per_sec  = models.FloatField(default=1.0)
    dns_server    = models.CharField(max_length=64, blank=True, default='system')
    seed_date     = models.DateField(null=True, blank=True)

    # ── Results summary ───────────────────────────────────────────────────────
    nxdomain_count  = models.IntegerField(default=0)
    resolved_count  = models.IntegerField(default=0)
    timeout_count   = models.IntegerField(default=0)
    error_count     = models.IntegerField(default=0)

    # NXDOMAIN ratio — key metric IDS uses to detect DGA
    # Values close to 1.0 (e.g. 0.96) are highly suspicious
    nxdomain_ratio  = models.FloatField(default=0.0)

    # Shannon entropy stats — IDS uses entropy to detect random-looking domains
    avg_entropy     = models.FloatField(default=0.0)
    max_entropy     = models.FloatField(default=0.0)
    min_entropy     = models.FloatField(default=0.0)

    # How long the test took
    duration_sec    = models.FloatField(default=0.0)

    # ── IDS detection tracking ────────────────────────────────────────────────
    # Was an IDS alert observed during this run?
    # You manually mark this after checking the IDS dashboard
    ids_detected        = models.BooleanField(null=True, blank=True)
    ids_detection_notes = models.TextField(blank=True, default='')

    # ── All domain results stored as JSON ────────────────────────────────────
    # Structure: [{"domain": "xkqpzmv.com", "outcome": "NXDOMAIN",
    #              "entropy": 3.91, "timestamp": "..."}, ...]
    domains_json = models.JSONField(default=list)

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return (
            f"DGA [{self.algorithm}] "
            f"{self.nxdomain_count}/{self.total_queries} NXDOMAIN "
            f"({self.nxdomain_ratio*100:.1f}%)"
        )

    @property
    def ids_status(self) -> str:
        if self.ids_detected is None:
            return 'Unknown'
        return 'Detected' if self.ids_detected else 'Evaded'

    @property
    def risk_level(self) -> str:
        """How suspicious this run would look to an IDS."""
        if self.nxdomain_ratio >= 0.8:
            return 'HIGH'
        elif self.nxdomain_ratio >= 0.5:
            return 'MEDIUM'
        else:
            return 'LOW'

    class Meta:
        ordering     = ['-created_at']
        verbose_name = 'DGA Result'
        verbose_name_plural = 'DGA Results'

# scanner/models.py — PASTE THIS at the bottom of your existing models.py

class ExfilTechnique(models.TextChoices):
    DNS  = 'dns',  'DNS Tunnelling'
    HTTP = 'http', 'HTTP Header Injection'
    ICMP = 'icmp', 'ICMP Payload Stuffing'


class ExfilProfile(models.TextChoices):
    BURST      = 'burst',      'Burst (maximum speed)'
    SLOW_DRIP  = 'slow_drip',  'Slow Drip (timed intervals)'
    JITTER     = 'jitter',     'Jitter (random delays)'


class ExfilResult(models.Model):
    """
    Stores the result of one complete exfiltration simulation run.
    One record per run — summary stats + all packet-level findings as JSON.
    """

    # ── Who ran it ────────────────────────────────────────────────────────────
    agent = models.ForeignKey(
        'Agent',
        on_delete    = models.SET_NULL,
        null         = True, blank = True,
        related_name = 'exfil_results',
    )

    # ── Configuration ─────────────────────────────────────────────────────────
    technique = models.CharField(
        max_length = 10,
        choices    = ExfilTechnique.choices,
        default    = ExfilTechnique.DNS,
    )
    profile = models.CharField(
        max_length = 20,
        choices    = ExfilProfile.choices,
        default    = ExfilProfile.BURST,
    )
    target          = models.CharField(max_length=255, blank=True)
    total_chunks    = models.IntegerField(default=0)
    successful      = models.IntegerField(default=0)
    errors          = models.IntegerField(default=0)
    duration_sec    = models.FloatField(default=0.0)
    avg_interval_sec = models.FloatField(default=0.0)

    # ── Detection surface ─────────────────────────────────────────────────────
    ids_severity    = models.CharField(max_length=20, blank=True)
    ids_signatures  = models.JSONField(default=list)

    # ── IDS tracking — filled in manually after checking IDS dashboard ────────
    ids_detected        = models.BooleanField(null=True, blank=True)
    ids_detection_notes = models.TextField(blank=True, default='')

    # ── Raw packet log ────────────────────────────────────────────────────────
    packets_json = models.JSONField(default=list)

    created_at = models.DateTimeField(auto_now_add=True)

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
        return (
            f"Exfil [{self.technique}/{self.profile}] "
            f"{self.successful}/{self.total_chunks} sent"
        )

    class Meta:
        ordering            = ['-created_at']
        verbose_name        = 'Exfil Result'
        verbose_name_plural = 'Exfil Results'