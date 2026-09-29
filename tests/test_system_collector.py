import pytest
from capx.core.collector.system_collector import SystemCollector

def test_system_collector_success():
    collector = SystemCollector()
    result = collector.collect()
    
    assert result["status"] == "success"
    assert "timestamp" in result
    assert "uptime_seconds" in result
    
    # Verify OS structure
    assert "os" in result
    assert "system" in result["os"]
    
    # Verify CPU structure
    assert "cpu" in result
    assert "usage_percent" in result["cpu"]
    assert isinstance(result["cpu"]["usage_percent"], float)
    
    # Verify Memory structure
    assert "memory" in result
    assert "usage_percent" in result["memory"]
    
    # Verify Disk structure
    assert "disk" in result
    assert "mountpoint" in result["disk"]