"""Replay all attack scenarios against the PLAIN agent and print the evidence.

Usage (from plain_agent/):  python -m attacks.run_attacks
State is written to plain_agent/state_attack_demo/ so your interactive state is untouched.
"""
import json
import shutil

import config
import seed_db
from attacks.scenarios import ALL


def main() -> None:
    demo_dir = config.BASE_DIR / "state_attack_demo"
    shutil.rmtree(demo_dir, ignore_errors=True)
    config.use_state_dir(demo_dir)
    print("PLAIN AGENT attack replay (ScriptedModel = fully persuaded LLM; evidence read from disk/DB)\n")
    for scenario in ALL:
        seed_db.seed()  # fresh DB per scenario
        result = scenario()
        print(f"=== {result['id']}  {result['name']}")
        print(f"    prompt: {result['prompt']}")
        for key, value in result.items():
            if key not in {"id", "name", "prompt"}:
                print(f"    {key}: {json.dumps(value, ensure_ascii=False, default=str)[:300]}")
        print()
    print(f"Evidence files: {config.OUTBOX_PATH}  {config.MEMORY_PATH}  {config.DB_PATH}")


if __name__ == "__main__":
    main()
