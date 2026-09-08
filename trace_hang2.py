"""Trace where django.setup() hangs by writing stack traces to a file."""
import os, sys, threading, time, traceback

project_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(project_dir)
sys.path.insert(0, project_dir)

log_file = os.path.join(project_dir, 'hang_trace.log')

def log(msg):
    with open(log_file, 'a') as f:
        f.write(f'{time.time():.3f}: {msg}\n')

def dump_stacks():
    """Dump all thread stack traces to log file."""
    with open(log_file, 'a') as f:
        f.write("\n=== STACK TRACE DUMP ===\n")
        for thread_id, frame in sys._current_frames().items():
            stack = traceback.format_stack(frame)
            thread_name = f"Thread-{thread_id}"
            for t in threading.enumerate():
                if t.ident == thread_id:
                    thread_name = t.name
                    break
            f.write(f"\n--- {thread_name} (ID: {thread_id}) ---\n")
            for line in stack[-20:]:
                f.write(line)
        f.write("\n=== END STACK DUMP ===\n")

log("Script started")

# Set timer to dump stacks after 15 seconds
timer = threading.Timer(15.0, dump_stacks)
timer.daemon = True
timer.start()

log("Loading settings...")
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.development'
from django.conf import settings
log(f"Settings loaded: {len(settings.INSTALLED_APPS)} apps")

import django
log("Calling django.setup()...")

try:
    django.setup()
    log("Django setup completed successfully!")
except Exception as e:
    log(f"Error: {e}")
    traceback.print_exc(file=open(log_file, 'a'))
finally:
    timer.cancel()
    log("Done")
