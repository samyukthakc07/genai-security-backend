"""Start both servers and report URLs."""
import os, sys, subprocess, time, urllib.request, socket

project_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(project_dir)

# Kill any existing processes on our ports
for port in [8000, 5173]:
    try:
        if os.name == 'nt':
            subprocess.run(f'netstat -ano | findstr :{port}', shell=True, capture_output=True)
    except:
        pass

# Start Django backend
print("Starting Django backend...", flush=True)
backend_log = open(os.path.join(project_dir, 'server_backend.log'), 'w', buffering=1)
backend = subprocess.Popen(
    [sys.executable, '-u', 'manage.py', 'runserver', '0.0.0.0:8000',
     '--settings=config.settings.development', '--noreload'],
    stdout=backend_log, stderr=subprocess.STDOUT, text=True,
    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
)
print(f"Backend PID: {backend.pid}", flush=True)

# Wait for backend by polling
start = time.time()
while time.time() - start < 60:
    try:
        resp = urllib.request.urlopen('http://localhost:8000/health/', timeout=2)
        if resp.status == 200:
            print(f"Backend ready! (took {time.time()-start:.1f}s)", flush=True)
            break
    except:
        time.sleep(2)
else:
    print("Backend didn't start in time, checking logs...", flush=True)
    with open(os.path.join(project_dir, 'server_backend.log')) as f:
        print(f.read()[-1000:], flush=True)
    backend.terminate()
    sys.exit(1)

# Start frontend
print("Starting frontend...", flush=True)
frontend_log = open(os.path.join(project_dir, 'server_frontend.log'), 'w', buffering=1)
os.chdir(os.path.join(project_dir, 'frontend'))
frontend = subprocess.Popen(
    ['npx.cmd', 'vite', '--host', '0.0.0.0', '--port', '5173'],
    stdout=frontend_log, stderr=subprocess.STDOUT, text=True, shell=True,
    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
)
print(f"Frontend PID: {frontend.pid}", flush=True)

# Wait for frontend
start = time.time()
while time.time() - start < 30:
    try:
        resp = urllib.request.urlopen('http://localhost:5173/', timeout=2)
        if resp.status == 200:
            print(f"Frontend ready! (took {time.time()-start:.1f}s)", flush=True)
            break
    except:
        time.sleep(2)
else:
    print("Frontend didn't start, checking logs...", flush=True)
    with open(os.path.join(project_dir, 'server_frontend.log')) as f:
        print(f.read()[-1000:], flush=True)

print("\n" + "="*50, flush=True)
print("  Backend API:  http://localhost:8000/", flush=True)
print("  API Health:   http://localhost:8000/health/", flush=True)
print("  Admin Panel:  http://localhost:8000/admin/", flush=True)
print("  Frontend:     http://localhost:5173/", flush=True)
print("="*50, flush=True)
print("\nServers running in background. Press Ctrl+C to stop.", flush=True)

try:
    while True:
        time.sleep(5)
        # Check both are still alive
        if backend.poll() is not None:
            print(f"Backend exited with code {backend.returncode}", flush=True)
            break
        if frontend.poll() is not None:
            print(f"Frontend exited with code {frontend.returncode}", flush=True)
            break
except KeyboardInterrupt:
    print("\nStopping...", flush=True)
    backend.terminate()
    frontend.terminate()
