#!/usr/bin/env python
"""Start the Django development server in the background."""
import os, sys, subprocess, time, signal

project_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(project_dir)
sys.path.insert(0, project_dir)

os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.development'

import threading

def consume_stream(stream, prefix):
    def run():
        try:
            for line in iter(stream.readline, ''):
                print(f"[{prefix}] {line}", end='', flush=True)
        except Exception:
            pass
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread

# First run migrations
print("Running migrations...", flush=True)
result = subprocess.run(
    [sys.executable, 'manage.py', 'migrate', '--settings=config.settings.development', '--verbosity=1'],
    capture_output=True, text=True, timeout=600
)
print(result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout, flush=True)
if result.stderr:
    print("STDERR:", result.stderr[-1000:] if len(result.stderr) > 1000 else result.stderr, flush=True)

print("\nStarting development server...", flush=True)
proc = subprocess.Popen(
    [sys.executable, 'manage.py', 'runserver', '0.0.0.0:8000', '--settings=config.settings.development', '--noreload'],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
)
consume_stream(proc.stdout, "BACKEND")

# Wait for it to start
time.sleep(10)
# Check if it's running
import urllib.request
try:
    resp = urllib.request.urlopen('http://localhost:8000/health/', timeout=5)
    print(f"Server is running! Status: {resp.status}", flush=True)
except Exception as e:
    print(f"Server check failed: {e}", flush=True)

print(f"\nServer PID: {proc.pid}", flush=True)
print("Keep this process running to serve requests.", flush=True)

# Keep running
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nShutting down...", flush=True)
    proc.terminate()
    proc.wait()

