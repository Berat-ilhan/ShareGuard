from __future__ import annotations


def main() -> int:
    from .ui import run_gui

    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
