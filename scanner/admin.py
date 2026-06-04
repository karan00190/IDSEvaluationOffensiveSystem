# scanner/admin.py
# ─────────────────────────────────────────────────────────────────────────────
#  Register models with Django's built-in admin panel.
#  Visit http://127.0.0.1:8000/admin to see this UI.
#
#  ModelAdmin lets you customise:
#    list_display  → which columns show in the list view
#    list_filter   → filter sidebar on the right
#    search_fields → search bar at the top
#    readonly_fields → fields that can't be edited
#    inlines       → show related records inside the parent record
# ─────────────────────────────────────────────────────────────────────────────

from django.contrib import admin
from .models import ScanRequest, HostResult, PortFinding
from .models import Agent
from .models import DGAResult


# ── Inline: show PortFindings inside HostResult page ────────────────────────
class PortFindingInline(admin.TabularInline):
    # TabularInline shows related records as a table inside the parent page
    model   = PortFinding
    extra   = 0          # don't show empty extra rows
    readonly_fields = (
        'port', 'protocol', 'state', 'service_name',
        'service_product', 'service_version', 'severity',
        'risk_note', 'is_critical_alert', 'alert_message',
    )
    can_delete = False


# ── Inline: show HostResults inside ScanRequest page ────────────────────────
class HostResultInline(admin.TabularInline):
    model   = HostResult
    extra   = 0
    readonly_fields = (
        'ip_address', 'hostname', 'status',
        'os_detected', 'host_risk', 'open_port_count',
    )
    can_delete = False
    show_change_link = True  # link to the HostResult detail page


# ── ScanRequest admin ────────────────────────────────────────────────────────
@admin.register(ScanRequest)
class ScanRequestAdmin(admin.ModelAdmin):

    # Columns shown in the list view
    list_display = (
        'id', 'target', 'scan_profile', 'status',
        'overall_risk', 'total_hosts', 'hosts_up',
        'total_open_ports', 'high_severity_count',
        'cache_hit', 'created_at', 'duration_seconds',
    )

    # Filter sidebar
    list_filter = ('status', 'scan_profile', 'overall_risk', 'cache_hit')

    # Search bar — searches these fields
    search_fields = ('target', 'token', 'user__username')

    # These fields cannot be edited in admin
    readonly_fields = (
        'token', 'created_at', 'started_at', 'completed_at',
        'duration_seconds', 'cache_hit', 'cached_from',
        'total_hosts', 'hosts_up', 'total_open_ports',
        'high_severity_count', 'medium_severity_count',
        'overall_risk', 'error_message',
    )

    # Show host results inside the scan detail page
    inlines = [HostResultInline]

    # Group fields into sections on the detail page
    fieldsets = (
        ('Scan Target', {
            'fields': ('user', 'target', 'scan_profile', 'token')
        }),
        ('Status', {
            'fields': ('status', 'error_message')
        }),
        ('Cache', {
            'fields': ('cache_hit', 'cached_from')
        }),
        ('Results Summary', {
            'fields': (
                'overall_risk', 'total_hosts', 'hosts_up',
                'total_open_ports', 'high_severity_count', 'medium_severity_count',
            )
        }),
        ('Timestamps', {
            'fields': ('created_at', 'started_at', 'completed_at', 'duration_seconds')
        }),
    )


# ── HostResult admin ─────────────────────────────────────────────────────────
@admin.register(HostResult)
class HostResultAdmin(admin.ModelAdmin):

    list_display = (
        'ip_address', 'hostname', 'status',
        'os_detected', 'host_risk', 'open_port_count',
        'scan', 'scanned_at',
    )

    list_filter  = ('status', 'host_risk')
    search_fields = ('ip_address', 'hostname', 'scan__target')
    readonly_fields = ('scanned_at',)

    # Show port findings inside the host detail page
    inlines = [PortFindingInline]


# ── PortFinding admin ────────────────────────────────────────────────────────
@admin.register(PortFinding)
class PortFindingAdmin(admin.ModelAdmin):

    list_display = (
        'port', 'protocol', 'state', 'service_name',
        'service_product', 'service_version',
        'severity', 'is_critical_alert',
        'host', 'found_at',
    )

    list_filter  = ('state', 'severity', 'protocol', 'is_critical_alert')
    search_fields = ('service_name', 'service_product', 'host__ip_address')
    readonly_fields = ('found_at', 'full_version')


@admin.register(Agent)
class AgentAdmin(admin.ModelAdmin):
    list_display = (
        'agent_id', 'name', 'is_active',
        'last_seen_at', 'last_seen_ip', 'total_requests',
        'registered_at',
    )
    list_filter  = ('is_active',)
    search_fields = ('agent_id', 'name', 'last_seen_ip')
    readonly_fields = (
        'auth_token', 'secret_key', 'registered_at',
        'last_seen_at', 'last_seen_ip', 'total_requests',
    )
    fieldsets = (
        ('Identity', {
            'fields': ('agent_id', 'name', 'is_active', 'registered_by')
        }),
        ('Credentials (read-only)', {
            'fields': ('auth_token', 'secret_key'),
            'classes': ('collapse',),   # collapsed by default for security
        }),
        ('Activity', {
            'fields': ('registered_at', 'last_seen_at', 'last_seen_ip', 'total_requests')
        }),
    )

# scanner/admin.py — ADD THIS at the bottom of your existing admin.py



@admin.register(DGAResult)
class DGAResultAdmin(admin.ModelAdmin):
    list_display  = (
        'pk', 'algorithm', 'total_queries',
        'nxdomain_count', 'nxdomain_ratio',
        'avg_entropy', 'ids_detected', 'risk_level',
        'agent', 'created_at',
    )
    list_filter   = ('algorithm', 'ids_detected')
    search_fields = ('agent__agent_id',)
    readonly_fields = (
        'nxdomain_count', 'resolved_count', 'timeout_count',
        'error_count', 'nxdomain_ratio', 'avg_entropy',
        'max_entropy', 'min_entropy', 'duration_sec',
        'domains_json', 'created_at', 'risk_level',
    )
    fieldsets = (
        ('Configuration', {
            'fields': ('agent', 'algorithm', 'total_queries',
                       'rate_per_sec', 'dns_server', 'seed_date'),
        }),
        ('Results', {
            'fields': ('nxdomain_count', 'resolved_count',
                       'timeout_count', 'error_count',
                       'nxdomain_ratio', 'duration_sec'),
        }),
        ('Entropy Analysis', {
            'fields': ('avg_entropy', 'max_entropy', 'min_entropy'),
        }),
        ('IDS Tracking', {
            'fields': ('ids_detected', 'ids_detection_notes'),
        }),
        ('Raw Data', {
            'fields': ('domains_json',),
            'classes': ('collapse',),
        }),
    )


# scanner/admin.py — PASTE THIS at the bottom of your existing admin.py

from .models import ExfilResult

@admin.register(ExfilResult)
class ExfilResultAdmin(admin.ModelAdmin):
    list_display  = (
        'pk', 'technique', 'profile', 'target',
        'total_chunks', 'successful', 'errors',
        'duration_sec', 'ids_detected', 'agent', 'created_at',
    )
    list_filter   = ('technique', 'profile', 'ids_detected')
    search_fields = ('target', 'agent__agent_id')
    readonly_fields = (
        'total_chunks', 'successful', 'errors',
        'duration_sec', 'avg_interval_sec',
        'ids_signatures', 'ids_severity',
        'packets_json', 'created_at', 'success_rate',
    )
    fieldsets = (
        ('Configuration', {
            'fields': ('agent', 'technique', 'profile', 'target'),
        }),
        ('Results', {
            'fields': (
                'total_chunks', 'successful', 'errors',
                'duration_sec', 'avg_interval_sec', 'success_rate',
            ),
        }),
        ('Detection Surface', {
            'fields': ('ids_severity', 'ids_signatures'),
        }),
        ('IDS Tracking', {
            'fields': ('ids_detected', 'ids_detection_notes'),
        }),
        ('Raw Packet Log', {
            'fields':  ('packets_json',),
            'classes': ('collapse',),
        }),
    )