#!/usr/bin/env python
"""Start backend and frontend dev servers."""
import os, sys, subprocess, time, signal, urllib.request, threading

project_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(project_dir)

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

# Start Django backend
print("Starting Django backend on port 8000...", flush=True)
backend = subprocess.Popen(
    [sys.executable, 'manage.py', 'runserver', '0.0.0.0:8000',
     '--settings=config.settings.development', '--noreload'],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
)
consume_stream(backend.stdout, "BACKEND")

# Wait for backend to start
time.sleep(15)

# Check backend
try:
    resp = urllib.request.urlopen('http://localhost:8000/health/', timeout=5)
    print(f"Backend: http://localhost:8000/health/ - Status: {resp.status}", flush=True)
except Exception as e:
    print(f"Backend check: {e}", flush=True)

# Start frontend
frontend_dir = os.path.join(project_dir, 'frontend')
print(f"Starting frontend in {frontend_dir}...", flush=True)
os.chdir(frontend_dir)
frontend = subprocess.Popen(
    ['npx', 'vite', '--port', '5178', '--host', '0.0.0.0'],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, shell=True
)
consume_stream(frontend.stdout, "FRONTEND")

time.sleep(10)

# Check frontend
try:
    resp = urllib.request.urlopen('http://localhost:5178/', timeout=5)
    print(f"Frontend: http://localhost:5178/ - Status: {resp.status}", flush=True)
except Exception as e:
    print(f"Frontend check: {e}", flush=True)

print("\n=== URLs ===", flush=True)
print("Backend API:  http://localhost:8000/", flush=True)
print("API Health:   http://localhost:8000/health/", flush=True)
print("API Admin:    http://localhost:8000/admin/", flush=True)
print("Frontend:     http://localhost:5178/", flush=True)
print("", flush=True)
print("Press Ctrl+C to stop both servers.", flush=True)

# Keep running
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nShutting down...", flush=True)
    backend.terminate()
    frontend.terminate()

