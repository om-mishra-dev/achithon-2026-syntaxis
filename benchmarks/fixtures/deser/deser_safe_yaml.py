"""DESER-002: Safe - yaml.safe_load does not allow arbitrary code execution."""
import yaml


def load_config(stream):
    return yaml.safe_load(stream)

