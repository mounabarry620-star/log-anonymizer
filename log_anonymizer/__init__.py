"""log-anonymizer : masquage des données sensibles dans les fichiers de logs."""

from .anonymizer import Anonymizer, Rule
from .rules import load_rules, default_rules

__all__ = ["Anonymizer", "Rule", "load_rules", "default_rules"]
__version__ = "0.1.0"
