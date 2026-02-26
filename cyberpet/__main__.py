"""Allow running the CLI as a module: python -m cyberpet.cli"""
from cyberpet.cli import main  # type: ignore[import]

if __name__ == "__main__":
    main()
