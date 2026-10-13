# backend/test_error.py
import pytest

def test_simulated_compiler_error():
    """
    Simulates a syntax error or broken fix introduced by the LLM patch.
    When this fails in the sandbox, the agentic loop catches the pytest failure,
    feeds the error back to the LLM, and triggers a retry/refine iteration.
    """
    # Deliberate syntax / assertion error to test agent retry loop
    assert 1 == 2, "Agentic Sandbox Error: Patch broke existing regression tests!"