#!/usr/bin/env python3

from src.cli import Cli
from src.core import Orchestrator

def main():
    config, args = Cli.parse_and_validate()
    Orchestrator.launch_modules(config, args.modules, args.targets, args.audit)

if __name__ == '__main__':
    main()