"""Entry point for halvard.exe. Imports nothing heavy until a story is chosen, so `--version` and the menu start instantly and use little memory."""
import sys

STORIES = ("setup", "demo", "stolen-session", "mailed-attachment", "exposed-bucket", "data-leak", "patch-day", "ai-agent", "tripwires", "platform", "rogue-device", "perf")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] in (["--version"], ["-V"]):
        from halvard import __version__
        print("Halvard", __version__); return 0
    if not argv or argv[0] in ("-h", "--help", "help", "list"):
        print("Halvard reference client. Usage: halvard <story>\nStories: " + ", ".join(STORIES)); return 0
    if argv[0] not in STORIES:
        print(f"Unknown story '{argv[0]}'. Run 'halvard list'."); return 2
    sys.argv = ["halvard"] + argv
    from halvard import cli
    cli.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
