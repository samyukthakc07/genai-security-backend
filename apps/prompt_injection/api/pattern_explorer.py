"""
Pattern Explorer — Exposes prompt injection pattern metadata and real-time matching.

Used by the interactive Pattern Explorer frontend page so users can type a prompt
and see which regex patterns match in real-time.
"""
import re
import logging
from typing import Any

from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.security_engine.plugins.prompt_injection import (
    _COMPILED_PATTERNS,
    SYSTEM_OVERRIDE_PATTERNS,
    JAILBREAK_PATTERNS,
    ROLE_PLAY_PATTERNS,
    CONTEXT_LEAKAGE_PATTERNS,
    PAYLOAD_SPLITTING_PATTERNS,
    ENCODED_PATTERNS,
    MULTI_LANGUAGE_PATTERNS,
    MALICIOUS_KEYWORDS,
    XML_HTML_INJECTION_PATTERNS,
)

logger = logging.getLogger(__name__)

# Pattern source references for metadata (descriptions, categories)
PATTERN_META: dict[str, list[tuple[str, str, float, str, str]]] = {
    'system_override': [
        (n, r, s, 'Matches attempts to override system instructions', '#ef4444')
        for n, r, s in SYSTEM_OVERRIDE_PATTERNS
    ],
    'jailbreak': [
        (n, r, s, 'Detects DAN mode, unfiltered access requests, and ethical bypasses', '#f97316')
        for n, r, s in JAILBREAK_PATTERNS
    ],
    'role_play': [
        (n, r, s, 'Catches persona adoption and deceptive role-play prompts', '#eab308')
        for n, r, s in ROLE_PLAY_PATTERNS
    ],
    'context_leakage': [
        (n, r, s, 'Flags attempts to extract system prompts or internal instructions', '#a855f7')
        for n, r, s in CONTEXT_LEAKAGE_PATTERNS
    ],
    'payload_splitting': [
        (n, r, s, 'Detects split/obfuscated instructions across multiple inputs', '#06b6d4')
        for n, r, s in PAYLOAD_SPLITTING_PATTERNS
    ],
    'encoded': [
        (n, r, s, 'Identifies base64, hex, and other obfuscated content', '#ec4899')
        for n, r, s in ENCODED_PATTERNS
    ],
    'multi_language': [
        (n, r, s, 'Flags multilingual attacks and translation-based bypasses', '#14b8a6')
        for n, r, s in MULTI_LANGUAGE_PATTERNS
    ],
    'malicious_keywords': [
        (n, r, s, 'Searches for sensitive keywords like API keys and credentials', '#8b5cf6')
        for n, r, s in MALICIOUS_KEYWORDS
    ],
    'html_injection': [
        (n, r, s, 'Detects HTML/XML injection vectors including XSS and XXE', '#dc2626')
        for n, r, s in XML_HTML_INJECTION_PATTERNS
    ],
}

# Human-readable category labels
CATEGORY_LABELS: dict[str, str] = {
    'system_override': 'System Override',
    'jailbreak': 'Jailbreak',
    'role_play': 'Role Play & Deception',
    'context_leakage': 'Context Leakage',
    'payload_splitting': 'Payload Splitting',
    'encoded': 'Encoded / Obfuscated',
    'multi_language': 'Multi-Language Attack',
    'malicious_keywords': 'Malicious Keywords',
    'html_injection': 'XML / HTML Injection',
}

CATEGORY_DESCRIPTIONS: dict[str, str] = {
    'system_override': 'Direct attempts to override or replace system instructions.',
    'jailbreak': 'DAN mode, unfiltered access, and ethical bypass techniques.',
    'role_play': 'Persona adoption and deceptive character role-play.',
    'context_leakage': 'Extraction of system prompts, instructions, or configuration.',
    'payload_splitting': 'Distributing malicious instructions across multiple inputs.',
    'encoded': 'Base64, hex, escape sequences, and other obfuscation.',
    'multi_language': 'Multilingual attacks and translation-based bypass attempts.',
    'malicious_keywords': 'Sensitive keywords indicating credential or data theft.',
    'html_injection': 'HTML/XML tag injection, XSS, XXE, and event handler abuse.',
}


class PatternsListView(APIView):
    """GET /api/v1/prompt-injection/patterns/ — returns all pattern categories and their patterns."""

    permission_classes = [permissions.AllowAny]

    def get(self, request):
        categories = []
        for category_name, patterns in PATTERN_META.items():
            pattern_list = []
            for name, regex_str, base_score, description, color in patterns:
                pattern_list.append({
                    'name': name,
                    'regex': regex_str,
                    'base_confidence': base_score,
                    'description': description,
                    'color': color,
                })
            categories.append({
                'id': category_name,
                'label': CATEGORY_LABELS.get(category_name, category_name.replace('_', ' ').title()),
                'description': CATEGORY_DESCRIPTIONS.get(category_name, ''),
                'pattern_count': len(pattern_list),
                'patterns': pattern_list,
            })
        return Response({
            'categories': categories,
            'total_patterns': sum(len(p) for p in PATTERN_META.values()),
            'total_categories': len(categories),
        })


class PatternsMatchView(APIView):
    """POST /api/v1/prompt-injection/patterns/match/ — match patterns against a prompt.

    Request:  {"text": "Your prompt here"}
    Response: List of all matched patterns with positions, snippets, confidence, etc.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        text = request.data.get('text', '').strip()
        if not text:
            return Response(
                {'error': 'text is required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        matches = []
        matched_ranges: list[tuple[int, int, str, str, float]] = []  # start, end, category, name, confidence

        for category_name, compiled_patterns in _COMPILED_PATTERNS.items():
            meta_patterns = PATTERN_META.get(category_name, [])
            meta_lookup = {n: (d, c) for n, _, _, d, c in meta_patterns}

            for name, pattern, regex_str, base_score in compiled_patterns:
                description, color = meta_lookup.get(name, ('', '#6b7280'))

                for match in pattern.finditer(text):
                    start, end = match.start(), match.end()
                    matched_text = match.group()
                    confidence = min(base_score + 0.10 if len(matched_text) > 50 else base_score, 1.0)

                    # Get snippet for context
                    ctx_start = max(0, start - 30)
                    ctx_end = min(len(text), end + 30)

                    matches.append({
                        'category_id': category_name,
                        'category_label': CATEGORY_LABELS.get(category_name, category_name),
                        'pattern_name': name,
                        'pattern_regex': regex_str,
                        'base_confidence': base_score,
                        'adjusted_confidence': round(confidence, 2),
                        'matched_text': matched_text,
                        'start_position': start,
                        'end_position': end,
                        'snippet': text[ctx_start:ctx_end],
                        'description': description,
                        'color': color,
                    })
                    matched_ranges.append((start, end, category_name, name, confidence))

        # Calculate aggregate risk
        risk_score = 0
        if matches:
            max_conf = max(m.get('adjusted_confidence', 0) for m in matches)
            category_count = len(set(m['category_id'] for m in matches))
            has_critical = any(m.get('adjusted_confidence', 0) >= 0.85 for m in matches)
            risk_score = min(max_conf * 100 + category_count * 5 + (10 if has_critical else 0), 100)

        # Determine injection type
        injection_type = 'none'
        type_priority = ['jailbreak', 'system_override', 'context_leakage', 'payload_splitting',
                         'encoded', 'multi_language', 'role_play', 'malicious_keywords', 'html_injection']
        high_conf_matches = [m for m in matches if m.get('adjusted_confidence', 0) >= 0.60]
        if high_conf_matches:
            for priority_cat in type_priority:
                if any(m['category_id'] == priority_cat for m in high_conf_matches):
                    injection_type = priority_cat
                    break
            if injection_type == 'none':
                injection_type = 'direct'

        return Response({
            'text': text,
            'matches': matches,
            'match_count': len(matches),
            'matched_categories': list(set(m['category_id'] for m in matches)),
            'aggregate_risk_score': round(risk_score, 1),
            'injection_type': injection_type,
            'is_malicious': risk_score >= 40,
        })
