import json
from pathlib import Path


def main() -> None:
    print(f"{'crash_id':<20} {'vulnerability_class':<20} {'accepted':<10}")
    print(f"{'-' * 20} {'-' * 20} {'-' * 10}")
    for path in sorted(Path("evidence").glob("*.json")):
        bundle = json.loads(path.read_text(encoding="utf-8"))
        diagnosis = bundle.get("diagnosis", {})
        validation = bundle.get("validation", {})
        accepted = all(
            validation.get(field, False)
            for field in ("builds", "crash_fixed", "regression_pass")
        )
        print(
            f"{bundle.get('crash', {}).get('crash_id', path.stem):<20} "
            f"{diagnosis.get('vulnerability_class', 'unknown'):<20} "
            f"{'FIXED' if accepted else 'UNRESOLVED':<10}"
        )


if __name__ == "__main__":
    main()
