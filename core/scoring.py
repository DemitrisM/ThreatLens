"""Confidence scoring engine.

Sums score_delta values from all module results, clamps the total to
0–100, assigns a risk band (LOW / MEDIUM / HIGH / CRITICAL), and
formats a human-readable score breakdown.
"""
