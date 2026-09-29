"""Direct entry point used by local development and Windows deployment."""

from shareguard.app import main


if __name__ == "__main__":
    raise SystemExit(main())
