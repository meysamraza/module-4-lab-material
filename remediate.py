import argparse
import json
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

THRESHOLD = 7.0
SEVERITY_SCORE = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}


def load_findings(args, inspector):
    if args.input:
        with open(args.input, "r", encoding="utf-8-sig") as f:
            return json.load(f).get("findings", [])
    findings = []
    paginator = inspector.get_paginator("list_findings")
    for page in paginator.paginate(
        filterCriteria={"findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]}
    ):
        findings.extend(page.get("findings", []))
    return findings


def get_score(finding):
    score = finding.get("inspectorScore")
    if score is not None:
        return float(score)
    cvss = finding.get("packageVulnerabilityDetails", {}).get("cvss", [])
    base = [c["baseScore"] for c in cvss if c.get("baseScore") is not None]
    if base:
        return float(max(base))
    return SEVERITY_SCORE.get(finding.get("severity", ""), 0.0)


def write_ticket(path, finding, score, resource, reason):
    ticket = {
        "ticket_id": "TCK-" + uuid.uuid4().hex[:8].upper(),
        "time": datetime.now(timezone.utc).isoformat(),
        "title": finding.get("title", "Unknown"),
        "severity": finding.get("severity", "UNKNOWN"),
        "score": score,
        "resource": resource.get("id", "unknown"),
        "reason": reason,
        "status": "OPEN",
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(ticket) + "\n")
    return ticket


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", help="Path to findings JSON. If missing, read live from Inspector.")
    p.add_argument("--region", default="eu-north-1")
    p.add_argument("--threshold", type=float, default=THRESHOLD)
    p.add_argument("--tickets", default="tickets.json")
    args = p.parse_args()

    inspector = boto3.client("inspector2", region_name=args.region)
    ec2 = boto3.client("ec2", region_name=args.region)

    findings = load_findings(args, inspector)
    print("Findings loaded: %d" % len(findings))

    for f in findings:
        score = get_score(f)
        resources = f.get("resources") or [{}]
        resource = resources[0]
        rid = resource.get("id", "unknown")
        rtype = resource.get("type", "unknown")
        title = f.get("title", "Unknown")
        sev = f.get("severity", "UNKNOWN")

        if score >= args.threshold and rtype == "AWS_EC2_INSTANCE":
            try:
                ec2.create_tags(
                    Resources=[rid],
                    Tags=[{"Key": "needs-patch", "Value": "true"}],
                )
                print("TAGGED | %s | %s | score %.1f | %s" % (sev, title, score, rid))
                continue
            except ClientError as e:
                reason = "Tagging failed: %s" % e.response["Error"]["Code"]
        elif score < args.threshold:
            reason = "Score %.1f below threshold %.1f" % (score, args.threshold)
        else:
            reason = "Resource type %s is not EC2" % rtype

        t = write_ticket(args.tickets, f, score, resource, reason)
        print("TICKET | %s | %s | score %.1f | %s | %s" % (sev, title, score, rid, t["ticket_id"]))


if __name__ == "__main__":
    main()
