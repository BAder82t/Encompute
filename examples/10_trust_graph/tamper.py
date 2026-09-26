"""Write a doctored copy of a trust bundle: tamper.py IN OUT ATTACK."""
import json
import sys

src, dst, attack = sys.argv[1:4]
bundle = json.load(open(src))
nodes = bundle["nodes"]


def privacy_receipt(asset):
    return next(k for k, v in nodes.items()
                if k.startswith("privacy:") and v["evidence"]["value"]["asset_id"] == asset)


if attack == "drop-privacy-receipt":
    # Hide that the release was charged to gradient-a's budget.
    k = privacy_receipt("gradient-a")
    del nodes[k]
    bundle["edges"] = [e for e in bundle["edges"] if k not in (e["from"], e["to"])]
elif attack == "less-noise":
    # Claim ten times the noise that was added.
    k = privacy_receipt("gradient-a")
    nodes[k]["evidence"]["value"]["mechanism"]["noise_multiplier"] = "60.0"
else:
    sys.exit(f"unknown attack {attack}")
json.dump(bundle, open(dst, "w"), indent=1)
