# app/otel_tracer.py
import os
import logging
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
from opentelemetry.sdk.resources import Resource

logger = logging.getLogger("vulnerability-lifecycle-otel")

def setup_gcp_opentelemetry(app=None):
    """Configures GCP Cloud Trace OpenTelemetry exporter for zero-cost production observability."""
    project_id = os.environ.get("GCP_PROJECT_ID", "")
    
    # Resource metadata for GCP Cloud Trace
    resource = Resource.create({"service.name": "shiftshield-vulnerability-engine"})
    provider = TracerProvider(resource=resource)
    
    try:
        # Uses GCP Workload Identity / Pod Service Account credentials automatically
        cloud_exporter = CloudTraceSpanExporter(project_id=project_id if project_id else None)
        provider.add_span_processor(BatchSpanProcessor(cloud_exporter))
        trace.set_tracer_provider(provider)
        logger.info("📡 GCP Cloud Trace OpenTelemetry Exporter initialized successfully.")
    except Exception as e:
        logger.warning(f"⚠️ Cloud Trace Exporter fallback: {e}")

    # Automatically instrument FastAPI request lifecycle
    if app:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)

tracer = trace.get_tracer("shiftshield-tracer")