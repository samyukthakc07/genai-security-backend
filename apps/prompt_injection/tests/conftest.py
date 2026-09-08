"""Configure Django for pytest tests."""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

# Need to configure Django before importing any Django/DRF modules
django.setup()
