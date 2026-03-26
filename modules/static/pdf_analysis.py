"""PDF analysis module.

Uses peepdf to inspect PDF object structure, extract embedded JavaScript,
detect launch/URI actions, and analyse stream entropy. Returns score_delta
for suspicious elements found.
"""
