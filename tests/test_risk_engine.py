import pytest
from capx.core.risk.scorer import RiskScorer

def test_risk_scorer():
    scorer = RiskScorer()
    
    mock_process = [{"severity": "WARNING"}]    # 15 points
    mock_network = [{"severity": "MONITOR"}]    # 5 points
    mock_startup = [{"severity": "CRITICAL"}]   # 35 points
    mock_detection = [{"severity": "WARNING"}]  # 15 points
    
    result = scorer.calculate_risk(mock_process, mock_network, mock_startup, mock_detection)
    
    assert result["status"] == "success"
    assert result["score"] == 70
    assert result["band"] == "WARNING"
    assert result["total_issues_evaluated"] == 4

def test_risk_scorer_max_cap():
    scorer = RiskScorer()
    mock_criticals = [{"severity": "CRITICAL"} for _ in range(4)]
    
    result = scorer.calculate_risk([], [], [], mock_criticals)
    
    assert result["score"] == 100
    assert result["band"] == "CRITICAL"