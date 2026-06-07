import logging
from typing import Any

from picosentry.serve.services.plugin_manager import PluginInterface

logger = logging.getLogger("picoshogun.Plugin.Test")

class TestHandler(PluginInterface):

    def initialize(self, config: dict[str, Any]) -> bool:
        logger.info("TestHandler initialized")
        return True

    def on_project_complete(self, project_id: str, result: dict) -> None:
        logger.info("[TestPlugin] Project %s completed: %s", project_id, result.get('status'))

    def on_alert(self, alert: dict) -> dict | None:
        logger.info("[TestPlugin] Alert: %s", alert.get('message', ''))
        return alert

    def health_check(self) -> dict:
        return {"status": "ok", "plugin": "test_plugin"}
