"""
PicoSentry — unified Pico Security Series.

Combines 4 tools into one package:
    scan      Supply-chain scanner [PicoSentry]
    sandbox   Runtime sandbox + behavioral analysis [PicoDome]
    watch     LLM prompt injection detection + output validation [PicoWatch]
    serve     API server, dashboard, orchestration [PicoShogun]

Usage:
    picosentry scan ./node_modules
    picosentry sandbox ./package
    picosentry watch scan-prompt --text "..."
    picosentry serve
"""

__version__ = "2.0.4"
