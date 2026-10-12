"""Interface en ligne de commande."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

from . import __version__
from .rules import build_anonymizer


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="log-anonymizer", description="Masque les données sensibles dans des logs.")
    p.add_argument("input", nargs="?", default="-", help="fichier d'entrée (défaut : stdin, ou '-')")
    p.add_argument("-o", "--output", default="-", help="fichier de sortie (défaut : stdout)")
    p.add_argument("-r", "--rules", help="fichier de règles YAML ou JSON (défaut : règles intégrées)")
    p.add_argument("-f", "--format", choices=["auto", "text", "json"], default="auto",
                   help="format des lignes : auto (défaut), text ou json (JSON-lines)")
    p.add_argument("-p", "--pseudonymize", action="store_true",
                   help="pseudonymisation cohérente : même valeur -> même jeton")
    p.add_argument("--salt", default=os.environ.get("LOG_ANONYMIZER_SALT", ""),
                   help="sel pour la pseudonymisation (ou variable LOG_ANONYMIZER_SALT)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        anon = build_anonymizer(args.rules, pseudonymize=args.pseudonymize, salt=args.salt)
    except (OSError, ValueError) as exc:
        print(f"erreur : règles invalides : {exc}", file=sys.stderr)
        return 2
    try:
        src = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8")
    except OSError as exc:
        print(f"erreur : {exc}", file=sys.stderr)
        return 1
    dst = sys.stdout if args.output == "-" else open(args.output, "w", encoding="utf-8")
    try:
        for line in anon.anonymize_lines(src, args.format):
            dst.write(line)
    except ValueError as exc:
        print(f"erreur : ligne JSON invalide : {exc}", file=sys.stderr)
        return 1
    finally:
        if src is not sys.stdin:
            src.close()
        if dst is not sys.stdout:
            dst.close()
    return 0
