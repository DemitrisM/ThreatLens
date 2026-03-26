"""Abstract base class for dynamic analysis providers.

Defines the interface that all dynamic backends (Speakeasy, VM worker,
CAPE) must implement: run(sample_path) and is_available().
"""
