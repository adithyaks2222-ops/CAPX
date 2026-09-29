import pytest
from capx.core.analysis.startup_analyzer import StartupAnalyzer

def test_startup_analyzer_logic():
    analyzer = StartupAnalyzer()
    
    mock_data = {
        "status": "success",
        "data": [
            # Normal application
            {"name": "SpotifyWebHelper", "target": "C:\\Program Files\\Spotify\\SpotifyWebHelper.exe"},
            # Suspicious Script
            {"name": "SystemUpdate", "target": "C:\\Users\\Public\\update.ps1"},
            # Suspicious Location
            {"name": "TempRunner", "target": "C:\\Users\\User\\AppData\\Local\\Temp\\malware.exe"}
        ]
    }
    
    result = analyzer.analyze(mock_data)
    
    assert result["status"] == "success"
    assert result["findings_count"] == 2
    
    finding_types = [f["type"] for f in result["findings"]]
    assert "SCRIPT_IN_STARTUP" in finding_types
    assert "SUSPICIOUS_STARTUP_LOCATION" in finding_types