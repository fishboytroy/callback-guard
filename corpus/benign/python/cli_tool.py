"""A small argparse CLI that formats numbers. No I/O beyond stdout."""
import argparse


def human(n: int) -> str:
    for unit in ("", "K", "M", "B"):
        if abs(n) < 1000:
            return f"{n}{unit}"
        n //= 1000
    return f"{n}T"


def main() -> None:
    parser = argparse.ArgumentParser(description="Format a number")
    parser.add_argument("value", type=int)
    args = parser.parse_args()
    print(human(args.value))


if __name__ == "__main__":
    main()
