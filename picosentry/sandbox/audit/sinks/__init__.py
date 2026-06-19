from picosentry.sandbox.audit.sinks.base import (
    SINK_REGISTRY,
    AuditSink,
    NullSink,
    SinkConfig,
    create_sink,
    register_sink,
)
from picosentry.sandbox.audit.sinks.file_sink import FileSink
from picosentry.sandbox.audit.sinks.syslog_sink import SyslogSink
from picosentry.sandbox.audit.sinks.webhook_sink import WebhookSink


register_sink("null", NullSink)
register_sink("file", FileSink)
register_sink("webhook", WebhookSink)
register_sink("syslog", SyslogSink)

__all__ = [
    "SINK_REGISTRY",
    "AuditSink",
    "FileSink",
    "NullSink",
    "SinkConfig",
    "SyslogSink",
    "WebhookSink",
    "create_sink",
    "register_sink",
]
