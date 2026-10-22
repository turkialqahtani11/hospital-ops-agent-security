"""Replay the attack scenarios against the SECURE agent and print the evidence.

Usage (from secure_agent/):  python -m attacks.run_attacks
State is written to secure_agent/state_attack_demo/ so your interactive state is untouched.
"""
import json
import shutil

import audit
import config
import seed_db
from attacks import scenarios


def main() -> None:
    demo_dir = config.BASE_DIR / "state_attack_demo"
    shutil.rmtree(demo_dir, ignore_errors=True)
    config.use_state_dir(demo_dir)
    print("SECURE AGENT attack replay (ScriptedModel = fully persuaded LLM; evidence read from disk/DB/audit)\n")
    for scenario in scenarios.ALL:
        scenarios.PASSWORDS.update(seed_db.seed(write_credentials_file=False))
        result = scenario()
        print(f"=== {result['id']} (mirrors {result['mirrors']})  {result['name']}   [user: {result['user']}]")
        print(f"    prompt: {result['prompt']}")
        for key, value in result.items():
            if key not in {"id", "name", "prompt", "mirrors", "user"}:
                print(f"    {key}: {json.dumps(value, ensure_ascii=False, default=str)[:400]}")
        print()
    ok, message = audit.verify_chain()
    print(f"{message}. Evidence files: {config.OUTBOX_PATH}  {config.AUDIT_PATH}  {config.DB_PATH}")


if __name__ == "__main__":
    main()
