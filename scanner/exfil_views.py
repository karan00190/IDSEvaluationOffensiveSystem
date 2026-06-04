# scanner/exfil_views.py
import logging
from django.shortcuts               import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http   import require_http_methods
from django.contrib                 import messages
from rest_framework.decorators      import api_view, authentication_classes, permission_classes
from rest_framework.permissions     import IsAuthenticated
from rest_framework.response        import Response
from rest_framework                 import status
from .models         import ExfilResult, ExfilTechnique, ExfilProfile, Agent
from .authentication import AgentAuthentication

logger = logging.getLogger(__name__)


# ── API: agent posts results ──────────────────────────────────────────────────

@api_view(['POST'])
@authentication_classes([AgentAuthentication])
@permission_classes([IsAuthenticated])
def api_exfil_results(request):
    agent     = request.user
    data      = request.data

    agent_model = None
    if hasattr(agent, 'agent_id'):
        try:
            agent_model = Agent.objects.get(agent_id=agent.agent_id)
        except Agent.DoesNotExist:
            pass

    tech_map = {
        'dns':  ExfilTechnique.DNS,
        'http': ExfilTechnique.HTTP,
        'icmp': ExfilTechnique.ICMP,
    }
    prof_map = {
        'burst':     ExfilProfile.BURST,
        'slow_drip': ExfilProfile.SLOW_DRIP,
        'jitter':    ExfilProfile.JITTER,
    }

    result = ExfilResult.objects.create(
        agent            = agent_model,
        technique        = tech_map.get(data.get('technique', 'dns'), ExfilTechnique.DNS),
        profile          = prof_map.get(data.get('profile', 'burst'), ExfilProfile.BURST),
        target           = data.get('target', ''),
        total_chunks     = data.get('total_chunks', 0),
        successful       = data.get('successful', 0),
        errors           = data.get('errors', 0),
        duration_sec     = data.get('duration_sec', 0.0),
        avg_interval_sec = data.get('avg_interval_sec', 0.0),
        ids_severity     = data.get('ids_severity', ''),
        ids_signatures   = data.get('ids_signatures', []),
        packets_json     = data.get('packets', []),
    )

    logger.info(
        f"Exfil result saved #{result.pk} "
        f"technique={result.technique} profile={result.profile} "
        f"sent={result.successful}/{result.total_chunks}"
    )

    return Response({
        'result_id': result.pk,
        'message':   f'Exfil results saved (ID: {result.pk})',
    }, status=status.HTTP_201_CREATED)


# ── Browser: dashboard ────────────────────────────────────────────────────────

@login_required
def exfil_dashboard(request):
    results       = ExfilResult.objects.select_related('agent').order_by('-created_at')
    total_runs    = results.count()
    detected      = results.filter(ids_detected=True).count()
    evaded        = results.filter(ids_detected=False).count()
    unknown       = results.filter(ids_detected__isnull=True).count()

    context = {
        'results':       results,
        'total_runs':    total_runs,
        'detected_runs': detected,
        'evaded_runs':   evaded,
        'unknown_runs':  unknown,
        'page':          'exfil',
    }
    return render(request, 'scanner/exfil_dashboard.html', context)


# ── Browser: detail ───────────────────────────────────────────────────────────

@login_required
def exfil_detail(request, pk):
    result  = get_object_or_404(ExfilResult, pk=pk)
    packets = result.packets_json or []
    context = {
        'result':  result,
        'packets': packets,
        'page':    'exfil',
    }
    return render(request, 'scanner/exfil_detail.html', context)


# ── Browser: mark IDS detection ───────────────────────────────────────────────

@login_required
@require_http_methods(['POST'])
def exfil_mark_detected(request, pk):
    result           = get_object_or_404(ExfilResult, pk=pk)
    detected         = request.POST.get('detected') == 'true'
    notes            = request.POST.get('notes', '')
    result.ids_detected        = detected
    result.ids_detection_notes = notes
    result.save(update_fields=['ids_detected', 'ids_detection_notes'])
    label = 'DETECTED by IDS' if detected else 'EVADED IDS'
    messages.success(request, f'Exfil Run #{pk} marked as: {label}')
    return redirect('scanner:exfil_detail', pk=pk)