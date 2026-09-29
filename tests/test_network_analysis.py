import pytest
from capx.core.analysis.network_analyzer import NetworkAnalyzer

def test_network_analyzer_logic():
    analyzer = NetworkAnalyzer()
    
    mock_data = {
        "status": "success",
        "data": [
            # Harmless local loopback
            {"pid": 100, "status": "LISTEN", "laddr": "127.0.0.1:8080", "lport": 8080},
            # Exposed random port
            {"pid": 101, "status": "LISTEN", "laddr": "0.0.0.0:8000", "lport": 8000},
            # Exposed sensitive port (RDP)
            {"pid": 102, "status": "LISTEN", "laddr": "0.0.0.0:3389", "lport": 3389},
            # Established connection
            {"pid": 103, "status": "ESTABLISHED", "laddr": "192.168.1.5:50000", "raddr": "8.8.8.8:443", "lport": 50000}
        ]
    }
    
    result = analyzer.analyze(mock_data)
    
    assert result["status"] == "success"
    assert result["findings_count"] == 2
    
    severities = [f["severity"] for f in result["findings"]]
    assert "MONITOR" in severities # For the port 8000
    assert "WARNING" in severities # For the port 3389