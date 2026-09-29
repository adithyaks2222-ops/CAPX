import pytest
from capx.core.analysis.process_analyzer import ProcessAnalyzer

def test_process_analyzer_thresholds():
    analyzer = ProcessAnalyzer(cpu_threshold=25.0, mem_threshold=20.0)
    
    mock_data = {
        "status": "success",
        "data": [
            {"pid": 100, "name": "normal.exe", "exe": "C:\\normal.exe", "cpu_percent": 5.0, "memory_percent": 10.0},
            {"pid": 101, "name": "heavy_cpu.exe", "exe": "C:\\heavy.exe", "cpu_percent": 90.0, "memory_percent": 5.0},
            {"pid": 102, "name": "sus.exe", "exe": None, "cpu_percent": 1.0, "memory_percent": 1.0}
        ]
    }
    
    result = analyzer.analyze(mock_data)
    
    assert result["status"] == "success"
    assert result["analyzed_count"] == 3
    assert result["findings_count"] == 2
    
    finding_types = [f["type"] for f in result["findings"]]
    assert "HIGH_CPU_PROCESS" in finding_types
    assert "MISSING_EXECUTABLE_PATH" in finding_types
    assert "HIGH_MEMORY_PROCESS" not in finding_types