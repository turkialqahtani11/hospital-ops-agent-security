"""Human approval console for email drafts. The LLM has no access to this program.

Usage:  python approve.py
Log in as an ops_manager of the same hospital who did NOT request the draft.
"""
import approvals
import config
from agent import login


def main() -> None:
    if not config.DB_PATH.exists():
        raise SystemExit("Database not found. Run: python seed_db.py")
    p = login()
    drafts = approvals.pending_drafts(p)
    if not drafts:
        print("No drafts pending approval for your hospital.")
        return
    for draft_id, requested_by, to, subject, body, created in drafts:
        print(f"\n=== Draft #{draft_id}  requested by {requested_by} at {created}")
        print(f"TO: {to}\nSUBJECT: {subject}\n{body}\n")
        answer = input("Approve and release to simulated outbox? [y/N] ").strip().lower()
        print(approvals.decide(p, draft_id, approve=(answer == "y")))


if __name__ == "__main__":
    main()
