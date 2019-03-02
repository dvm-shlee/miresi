# Miscellaneous Remote System Interface

from .client import SSH, SLURM
from .interface import SSHInterface, SLURMInterface

__version__ = '0.0.1'
__all__ = ['SSHInterface', 'SSH', 'SLURM', 'SLURMInterface']

# TODO: Better docstring, more clients (Google -cloud- compatible)
