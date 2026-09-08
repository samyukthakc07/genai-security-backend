import os, sys, time

# Change to the project directory
project_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(project_dir)
sys.path.insert(0, project_dir)

os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.development'

print(f'CWD: {os.getcwd()}', flush=True)
print(f'SYS.PATH first entry: {sys.path[0]}', flush=True)

from django.conf import settings
print(f'Settings loaded: {len(settings.INSTALLED_APPS)} apps', flush=True)

import django
print('Calling django.setup()...', flush=True)
start = time.time()
django.setup()
elapsed = time.time() - start
print(f'Django setup OK! Took {elapsed:.2f}s', flush=True)
print(f'Registered: {len(django.apps.apps.get_app_configs())} apps', flush=True)
