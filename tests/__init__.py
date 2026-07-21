"""Solslot API test package.

Some integration tests share deterministic fixture builders via ``tests.*``
imports. Keeping this directory explicit prevents an unrelated installed or
adjacent repository package named ``tests`` from being imported instead.
"""
