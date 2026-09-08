#!/usr/bin/env python
"""Run the Django development server and print output."""
import os, sys, subprocess, time

project_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(project_dir)

os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.development'

print("Starting Django development server...", flush=True)
proc = subprocess.Popen(
    [sys.executable, '-u', 'manage.py', 'runserver', '0.0.0.0:8000', 
     '--settings=config.settings.development', '--noreload', '--verbosity=3'],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
)

# Read output line by line
start = time.time()
server_ready = False
try:
    for line in iter(proc.stdout.readline, ''):
        elapsed = time.time() - start
        print(f'[{elapsed:.1f}s] {line}', end='', flush=True)
        if not server_ready and ('Quit the server' in line or 'Starting development server' in line):
            print("\n*** SERVER IS RUNNING! ***", flush=True)
            server_ready = True
        if not server_ready and elapsed > 120:
            print("\n*** TIMEOUT - Server didn't start within 120s ***", flush=True)
            proc.kill()
            break
except KeyboardInterrupt:
    print("\nStopping server...", flush=True)
    proc.terminate()

proc.wait()

