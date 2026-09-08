"""Trace where django.setup() hangs by dumping stack traces after timeout."""
import os, sys, threading, time, traceback

project_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(project_dir)
sys.path.insert(0, project_dir)

os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.development'

def dump_stacks():
    """Dump all thread stack traces."""
    print("\n=== STACK TRACE DUMP ===", flush=True)
    for thread_id, frame in sys._current_frames().items():
        stack = traceback.format_stack(frame)
        thread_name = f"Thread-{thread_id}"
        # Try to get thread name
        for t in threading.enumerate():
            if t.ident == thread_id:
                thread_name = t.name
                break
        print(f"\n--- {thread_name} (ID: {thread_id}) ---", flush=True)
        for line in stack[-15:]:  # Show last 15 lines
            print(line, end='', flush=True)
    print("\n=== END STACK DUMP ===", flush=True)

# Set timer to dump stacks after 15 seconds
timer = threading.Timer(15.0, dump_stacks)
timer.daemon = True
timer.start()

print(f"Loading settings...", flush=True)
from django.conf import settings
print(f"Settings loaded: {len(settings.INSTALLED_APPS)} apps", flush=True)

import django
print(f"Calling django.setup()...", flush=True)
sys.stdout.flush()

try:
    django.setup()
    print(f"Django setup completed successfully!", flush=True)
except Exception as e:
    print(f"Error: {e}", flush=True)
    traceback.print_exc()
finally:
    timer.cancel()
