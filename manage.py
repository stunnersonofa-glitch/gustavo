#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gustavo.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
git init
git remote remove origin
git remote add origin https://github.com/Stunnersonof/Stunner-GodMode-Capital.git
git add .
git commit -m "Brand upgrade: GodMode activated"
git push -u origin main
git init
git remote add origin https://github.com/Stunnersonof/Stunner-GodMode-Capital.git
git add .
git commit -m "Brand upgrade: GodMode activated"
git branch -M main
git push -u origin maingit init
git remote add origin https://github.com/Stunnersonof/Stunner-GodMode-Capital.git
git add .
git commit -m "Brand upgrade: GodMode activated"