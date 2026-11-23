"""
Security Attack Testbench Runner
Starts AS, runs attack_tests.py, captures output, and saves to attack_tests_output.txt.
"""
import subprocess
import sys
import os
import time

BASE_DIR = r"C:\Users\Srikrishna\Desktop\BTP\Implementation\hardware_experiment"
os.chdir(BASE_DIR)

print("Starting AS Server for attack tests...")
as_proc = subprocess.Popen(
    [sys.executable, "as_server.py", "--runs", "20", "--warmup", "0"],
    cwd=BASE_DIR,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

time.sleep(2)

print("Running attack tests against AS Server...")
env = os.environ.copy()
env['AS_HOST'] = '127.0.0.1'

attack_proc = subprocess.run(
    [sys.executable, "attack_tests.py"],
    cwd=BASE_DIR,
    env=env,
    capture_output=True,
    text=True
)

print(attack_proc.stdout)

# Terminate AS
as_proc.terminate()
try:
    as_out, _ = as_proc.communicate(timeout=3)
except:
    as_proc.kill()
    as_out, _ = as_proc.communicate()

# Save combined output
output_file = os.path.join(BASE_DIR, "attack_tests_output.txt")
with open(output_file, "w", encoding="utf-8") as f:
    f.write("=== EAP-IMP IMPLEMENTATION SECURITY ATTACK TESTBENCH ===\n\n")
    f.write(attack_proc.stdout)
    f.write("\n=== AUTHENTICATION SERVER EXECUTION LOG ===\n\n")
    f.write(as_out)

print(f"\nSaved attack test results to: {output_file}")

