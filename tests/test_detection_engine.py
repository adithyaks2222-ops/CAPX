import pytest
from capx.core.detection.anomaly_engine import AnomalyEngine

def test_anomaly_engine_correlation():
    engine = AnomalyEngine()
    
    mock_process_analysis = {
        "findings": [
            {"type": "MISSING_EXECUTABLE_PATH", "source": "PID:9999 (HiddenApp)"}
        ]
    }
    mock_network_analysis = {
        "findings": [
            {"type": "OPEN_LISTENING_PORT", "source": "PID:9999 | Port:4444"}
        ]
    }
    mock_startup_analysis = {"findings": []}
    
    result = engine.correlate(mock_process_analysis, mock_network_analysis, mock_startup_analysis)
    
    assert result["status"] == "success"
    assert result["alerts_count"] == 1
    assert result["alerts"][0]["type"] == "CORRELATED_HIDDEN_LISTENER"
    assert result["alerts"][0]["severity"] == "CRITICAL"