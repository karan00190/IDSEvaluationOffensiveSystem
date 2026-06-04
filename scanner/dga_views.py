# scanner/dga_views.py
# =============================================================================
#  MIAT — DGA Views
#
#  Two types of views in this file:
#    1. API view  — agent posts DGA results to /api/agent/dga/results/
#    2. Browser views — staff views the DGA results dashboard
# =============================================================================

import json
import logging
from datetime import date

from django.shortcuts               import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http   import require_http_methods
from django.contrib                 import messages
from django.utils                   import timezone

from rest_framework.decorators  import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response    import Response
from rest_framework             import status

from .models         import DGAResult, DGAAlgorithm, Agent
from .authentication import AgentAuthentication

logger = logging.getLogger(__name__)


# =============================================================================
# API VIEW — agent posts DGA results here
# POST /api/agent/dga/results/
# =============================================================================

@api_view(['POST'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def api_dga_results(request):
    """
    Agent posts the complete DGA test summary here after a run finishes.

    Request body (JSON):
    {
        "algorithm":     "date_seed",
        "total_queries": 50,
        "nxdomain":      48,
        "resolved":      2,
        "timeout":       0,
        "errors":        0,
        "nxdomain_ratio": 0.96,
        "avg_entropy":   3.91,
        "max_entropy":   3.97,
        "min_entropy":   3.82,
        "duration_sec":  52.3,
        "rate_per_sec":  1.0,
        "dns_server":    "192.168.1.1",
        "domains":       [{"domain": "...", "outcome": "NXDOMAIN", ...}, ...]
    }
    """
    agent = request.user   # authenticated Agent from AgentAuthentication
    data  = request.data

    # Look up the agent model instance
    agent_model = None
    if hasattr(agent, 'agent_id'):
        try:
            agent_model = Agent.objects.get(agent_id=agent.agent_id)
        except Agent.DoesNotExist:
            pass

    # Map algorithm string to DGAAlgorithm choice
    algo_map = {
        'date_seed': DGAAlgorithm.DATE_SEED,
        'xor_lcg':   DGAAlgorithm.XOR_LCG,
        'wordlist':  DGAAlgorithm.WORDLIST,
    }
    algorithm = algo_map.get(
        data.get('algorithm', 'date_seed'),
        DGAAlgorithm.DATE_SEED
    )

    # Create DGAResult record
    result = DGAResult.objects.create(
        agent          = agent_model,
        algorithm      = algorithm,
        total_queries  = data.get('total_queries', 0),
        rate_per_sec   = data.get('rate_per_sec',  1.0),
        dns_server     = data.get('dns_server',    'system'),
        seed_date      = date.today(),
        nxdomain_count = data.get('nxdomain',      0),
        resolved_count = data.get('resolved',      0),
        timeout_count  = data.get('timeout',       0),
        error_count    = data.get('errors',         0),
        nxdomain_ratio = data.get('nxdomain_ratio', 0.0),
        avg_entropy    = data.get('avg_entropy',    0.0),
        max_entropy    = data.get('max_entropy',    0.0),
        min_entropy    = data.get('min_entropy',    0.0),
        duration_sec   = data.get('duration_sec',  0.0),
        domains_json   = data.get('domains',       []),
    )

    logger.info(
        f"DGA results saved: #{result.pk} "
        f"algorithm={algorithm} "
        f"NXDOMAIN={result.nxdomain_count}/{result.total_queries} "
        f"ratio={result.nxdomain_ratio}"
    )

    return Response({
        'result_id': result.pk,
        'message':   f'DGA results saved (ID: {result.pk})',
        'summary': {
            'algorithm':      result.algorithm,
            'total_queries':  result.total_queries,
            'nxdomain_ratio': result.nxdomain_ratio,
            'avg_entropy':    result.avg_entropy,
            'risk_level':     result.risk_level,
        }
    }, status=status.HTTP_201_CREATED)


# =============================================================================
# BROWSER VIEWS — staff views DGA results dashboard
# =============================================================================

@login_required
def dga_dashboard(request):
    """
    Main DGA results page — lists all DGA test runs with summary stats.
    GET /dga/
    """
    results = DGAResult.objects.select_related('agent').order_by('-created_at')

    # Summary stats for the top cards
    total_runs       = results.count()
    detected_runs    = results.filter(ids_detected=True).count()
    evaded_runs      = results.filter(ids_detected=False).count()
    unknown_runs     = results.filter(ids_detected__isnull=True).count()
    high_risk_runs   = [r for r in results if r.risk_level == 'HIGH']

    context = {
        'results':        results,
        'total_runs':     total_runs,
        'detected_runs':  detected_runs,
        'evaded_runs':    evaded_runs,
        'unknown_runs':   unknown_runs,
        'high_risk_count': len(high_risk_runs),
        'page':           'dga',
    }
    return render(request, 'scanner/dga_dashboard.html', context)


@login_required
def dga_detail(request, pk):
    """
    Detail page for one DGA test run.
    Shows all domain-level findings in a table.
    GET /dga/<pk>/
    """
    result  = get_object_or_404(DGAResult, pk=pk)
    domains = result.domains_json or []

    # Separate by outcome for the counts
    nxdomains = [d for d in domains if d.get('outcome') == 'NXDOMAIN']
    resolved  = [d for d in domains if d.get('outcome') == 'RESOLVED']
    timeouts  = [d for d in domains if d.get('outcome') == 'TIMEOUT']

    context = {
        'result':    result,
        'domains':   domains,
        'nxdomains': nxdomains,
        'resolved':  resolved,
        'timeouts':  timeouts,
        'page':      'dga',
    }
    return render(request, 'scanner/dga_detail.html', context)


@login_required
@require_http_methods(['POST'])
def dga_mark_detected(request, pk):
    """
    Mark a DGA run as detected or evaded by the IDS.
    You call this after manually checking the IDS dashboard.
    POST /dga/<pk>/mark/
    """
    result    = get_object_or_404(DGAResult, pk=pk)
    detected  = request.POST.get('detected') == 'true'
    notes     = request.POST.get('notes', '')

    result.ids_detected        = detected
    result.ids_detection_notes = notes
    result.save(update_fields=['ids_detected', 'ids_detection_notes'])

    status_str = 'DETECTED by IDS' if detected else 'EVADED IDS'
    messages.success(request, f'DGA Run #{pk} marked as: {status_str}')

    return redirect('scanner:dga_detail', pk=pk)