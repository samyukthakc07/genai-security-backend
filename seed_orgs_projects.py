"""
Seed additional Organizations and Projects for a richer demo.
Adds 3 new organizations (total 4) and 6 new projects (total 7).

Usage:
    python seed_orgs_projects.py
"""

import os
import sys
import uuid
from datetime import datetime, timedelta
import random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

import django
django.setup()

from django.contrib.auth import get_user_model
from django.utils import timezone
from apps.organizations.models import Organization, Membership
from apps.projects.models import Project

User = get_user_model()


def seed():
    print("=" * 60)
    print("[Seed] Organizations & Projects for Demo")
    print("=" * 60)

    admin = User.objects.filter(email='admin@kct.ac.in').first()
    if not admin:
        print("[ERROR] Admin user not found. Run seed_data.py first.")
        return

    # Create a few extra users to be members of the new orgs
    extra_users = []
    extra_user_data = [
        ('sarah@kct.ac.in', 'Sarah', 'Chen'),
        ('mike@kct.ac.in', 'Mike', 'Rodriguez'),
        ('lisa@kct.ac.in', 'Lisa', 'Mendoza'),
        ('tom@kct.ac.in', 'Tom', 'Williams'),
        ('priya@kct.ac.in', 'Priya', 'Sharma'),
    ]
    for email, first, last in extra_user_data:
        u, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': email.split('@')[0],
                'first_name': first,
                'last_name': last,
            }
        )
        if created:
            u.set_password('Demo1234!')
            u.save()
            print(f"  [OK] Created user: {email}")
        extra_users.append(u)

    # ---- New Organizations ----
    new_orgs = [
        {
            'name': 'KCT AI Research Lab',
            'slug': 'kct-ai-research',
            'description': 'KCT research lab specializing in LLM-powered academic research, student projects, and real-world AI applications in education.',
            'industry': 'Education / AI Research',
            'subscription_tier': 'enterprise',
        },
        {
            'name': 'KCT Department of CSE',
            'slug': 'kct-cse',
            'description': 'Computer Science & Engineering department leveraging AI for research projects, curriculum development, and academic administration.',
            'industry': 'Education / Computer Science',
            'subscription_tier': 'professional',
        },
        {
            'name': 'KCT Innovation Hub',
            'slug': 'kct-innovation',
            'description': 'KCT startup incubator and innovation hub supporting AI-driven student startups, research commercialization, and industry collaborations.',
            'industry': 'Education / Innovation',
            'subscription_tier': 'enterprise',
        },
    ]

    created_orgs = []
    for org_data in new_orgs:
        org, was_created = Organization.objects.get_or_create(
            name=org_data['name'],
            defaults={
                'slug': org_data['slug'],
                'description': org_data['description'],
                'industry': org_data['industry'],
                'subscription_tier': org_data['subscription_tier'],
                'is_active': True,
            }
        )
        if was_created:
            print(f"  [NEW] Organization: {org.name} ({org.industry})")
        else:
            print(f"  [EXISTS] Organization: {org.name}")

        # Add admin as owner
        Membership.objects.get_or_create(
            organization=org,
            user=admin,
            defaults={'role': 'owner', 'is_default': True}
        )

        # Add extra users as members
        for u in random.sample(extra_users, random.randint(2, 4)):
            Membership.objects.get_or_create(
                organization=org,
                user=u,
                defaults={'role': random.choice(['admin', 'member', 'viewer'])}
            )

        created_orgs.append(org)

    # Get the existing org too
    kct_lab = Organization.objects.filter(name='KCT AI Security Lab').first()
    all_orgs = [kct_lab] + created_orgs if kct_lab else created_orgs

    # ---- New Projects ----
    projects_data = [
        # Org 1: KCT AI Security Lab (existing org)
        {
            'org': kct_lab,
            'name': 'KCT LLM Fine-Tuning Security Review',
            'description': 'Security assessment of KCT LLM fine-tuning pipeline including data validation, prompt injection testing, and output sanitization checks for campus AI systems.',
            'project_type': 'ai_security',
            'status': 'active',
            'days_back': 5,
        },
        {
            'org': kct_lab,
            'name': 'KCT Academic Compliance Review 2026',
            'description': 'Quarterly academic compliance assessment covering all AI model deployments and student data processing pipelines at KCT.',
            'project_type': 'compliance',
            'status': 'active',
            'days_back': 10,
        },

        # Org 2: KCT AI Research Lab
        {
            'org': created_orgs[0] if len(created_orgs) > 0 else None,
            'name': 'KCT Student Research Bot Audit',
            'description': 'Full security audit of LLM-powered student research assistant including prompt injection resistance, data leakage prevention, and output handling.',
            'project_type': 'ai_security',
            'status': 'active',
            'days_back': 3,
        },
        {
            'org': created_orgs[0] if len(created_orgs) > 0 else None,
            'name': 'KCT Academic API Security Scan',
            'description': 'Security assessment of academic API endpoints for prompt injection, data poisoning, and unbounded token consumption risks in campus systems.',
            'project_type': 'audit',
            'status': 'completed',
            'days_back': 20,
        },

        # Org 3: KCT Department of CSE
        {
            'org': created_orgs[1] if len(created_orgs) > 1 else None,
            'name': 'KCT CSE Research Model Hardening',
            'description': 'Security review of ML-based academic research models including adversarial testing, data poisoning prevention, and model extraction protection.',
            'project_type': 'ai_security',
            'status': 'active',
            'days_back': 2,
        },
        {
            'org': created_orgs[1] if len(created_orgs) > 1 else None,
            'name': 'KCT Curriculum AI Compliance',
            'description': 'Regulatory compliance assessment for AI-powered curriculum systems covering data privacy and academic standards.',
            'project_type': 'compliance',
            'status': 'active',
            'days_back': 7,
        },

        # Org 4: KCT Innovation Hub
        {
            'org': created_orgs[2] if len(created_orgs) > 2 else None,
            'name': 'KCT Startup AI Hallucination Assessment',
            'description': 'Critical hallucination and misinformation assessment of AI systems used in KCT student startups and innovation projects.',
            'project_type': 'ai_security',
            'status': 'active',
            'days_back': 1,
        },
        {
            'org': created_orgs[2] if len(created_orgs) > 2 else None,
            'name': 'KCT Student Data Privacy Audit',
            'description': 'Privacy audit of AI systems handling student data including encryption, access controls, and data leakage testing for compliance.',
            'project_type': 'audit',
            'status': 'completed',
            'days_back': 15,
        },
    ]

    project_count = 0
    for p in projects_data:
        if p['org'] is None:
            continue
        proj, was_created = Project.objects.get_or_create(
            name=p['name'],
            organization=p['org'],
            defaults={
                'description': p['description'],
                'project_type': p['project_type'],
                'status': p['status'],
                'created_by': admin,
                'created_at': timezone.now() - timedelta(days=p['days_back']),
            }
        )
        if was_created:
            print(f"  [NEW] Project: {p['name']} ({p['org'].name})")
            project_count += 1
        else:
            print(f"  [EXISTS] Project: {p['name']}")

    # ---- Summary ----
    print()
    print("=" * 60)
    print("[Summary]")
    print("=" * 60)
    for org in Organization.objects.all():
        member_count = org.memberships.count()
        proj_count = org.projects.count()
        print(f"  {org.name}: {member_count} members, {proj_count} projects")
    print(f"  Total Organizations: {Organization.objects.count()}")
    print(f"  Total Projects: {Project.objects.count()}")
    print(f"  Total Users: {User.objects.count()}")
    print("=" * 60)
    print("[Done] Additional seed data created!")


if __name__ == '__main__':
    seed()
