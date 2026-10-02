import pytest
from capx.core.optimization.optimizer import SafeOptimizer

def test_safety_validation():
    opt = SafeOptimizer()
    
    # Should block kernel PIDs
    assert opt.is_safe_to_terminate(4, "System") == False
    
    # Should block critical names regardless of PID
    assert opt.is_safe_to_terminate(9999, "explorer.exe") == False
    assert opt.is_safe_to_terminate(5555, "svchost.exe") == False
    
    # Should allow standard user-space apps
    assert opt.is_safe_to_terminate(12345, "chrome.exe") == True
    assert opt.is_safe_to_terminate(8888, "malware.exe") == True