import os, sys, time

project_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(project_dir)
sys.path.insert(0, project_dir)

os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings_minimal_copy'
# This will be a copy of base.py with minimal apps

# Let's just test with the minimal settings.py plus a few custom apps
import importlib.util

# First, load the minimal settings
spec = importlib.util.spec_from_file_location('test_minimal', 'config/settings.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Now modify INSTALLED_APPS to include our custom apps
mod.INSTALLED_APPS = list(mod.INSTALLED_APPS) + [
    'rest_framework',
    'corsheaders',
    'apps.core',
]

import django
from django.conf import settings
settings._setup(name='test_minimal')
# Manually override
settings.INSTALLED_APPS = mod.INSTALLED_APPS
settings.DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}}
settings.AUTH_USER_MODEL = 'core.User'

print(f'Testing with: {mod.INSTALLED_APPS}', flush=True)
print(f'Installed apps count: {len(settings.INSTALLED_APPS)}', flush=True)

print('Calling django.setup()...', flush=True)
start = time.time()
django.setup()
elapsed = time.time() - start
print(f'Django setup OK! Took {elapsed:.2f}s', flush=True)
