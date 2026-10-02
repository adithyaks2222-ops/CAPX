import pytest
from capx.core.recommendations.engine import RecommendationEngine

def test_recommendation_engine():
    engine = RecommendationEngine()
    
    mock_process = [{"type": "HIGH_CPU_PROCESS", "severity": "WARNING", "source": "PID:123"}]
    mock_network = []
    mock_startup = []
    mock_detection = [{"type": "CORRELATED_HIDDEN_LISTENER", "severity": "CRITICAL", "source": "PID:999"}]
    
    result = engine.generate_recommendations(mock_process, mock_network, mock_startup, mock_detection)
    
    assert result["status"] == "success"
    assert result["count"] == 2
    
    # Verify sorting by priority (CRITICAL should be first)
    assert result["recommendations"][0]["priority"] == "CRITICAL"
    assert "isolate the machine" in result["recommendations"][0]["action"].lower()
    
    assert result["recommendations"][1]["priority"] == "WARNING"
    assert "terminating this process" in result["recommendations"][1]["action"].lower()