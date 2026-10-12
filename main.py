"""
TrailHunter – AWS Cloud Telemetry & Detection Engine
Entry point.
"""

import json
import logging
import sys

import click
import yaml
from rich.console import Console
from rich.table import Table

from trailhunter.ingestor import CloudTrailIngestor
from trailhunter.normalizer import normalize
from trailhunter.baseliner import ActivityBaseliner
from trailhunter.detector import DetectionEngine

console = Console()
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")


def load_config(config_path: str) -> dict:
    with open(config_path, "r") as fh:
        return yaml.safe_load(fh)


@click.command()
@click.option("--source", type=click.Choice(["s3", "api", "local"]), required=True,
              help="CloudTrail log source.")
@click.option("--bucket", default=None, help="S3 bucket name (for --source s3).")
@click.option("--path", default=None, help="Local file or directory path (for --source local).")
@click.option("--config", default="config.yaml", show_default=True, help="Config file path.")
@click.option("--rules", default=None, help="Override rules directory from config.")
@click.option("--output", default=None, help="Write JSON alerts to this file.")
@click.option("--verbose", is_flag=True, help="Enable debug logging.")
def main(source, bucket, path, config, rules, output, verbose):
    """TrailHunter: ingest AWS CloudTrail telemetry and fire detection rules."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cfg = load_config(config)
    if bucket:
        cfg["cloudtrail"]["bucket"] = bucket
    rules_dir = rules or cfg.get("rules_dir", "trailhunter/rules/")

    ingestor = CloudTrailIngestor(cfg)
    baseliner = ActivityBaseliner(
        std_dev_threshold=cfg.get("baseliner", {}).get("std_dev_threshold", 3.0),
        min_events=cfg.get("baseliner", {}).get("min_events_threshold", 10),
    )
    engine = DetectionEngine(rules_dir)

    console.print(f"[bold cyan]TrailHunter[/bold cyan] — source: [yellow]{source}[/yellow]")

    if source == "s3":
        events = ingestor.ingest_from_s3()
    elif source == "api":
        events = ingestor.ingest_from_api()
    else:
        if not path:
            console.print("[red]--path is required for --source local[/red]")
            sys.exit(1)
        events = ingestor.ingest_from_local(path)

    all_alerts = []
    event_count = 0
    for raw_event in events:
        event_count += 1
        normalized = normalize(raw_event)
        baseliner.record(normalized)
        alerts = engine.evaluate(normalized)
        all_alerts.extend(alerts)

    baseliner.commit_window()

    console.print(f"Processed [bold]{event_count}[/bold] events. Found [bold red]{len(all_alerts)}[/bold red] alerts.\n")

    if all_alerts:
        _print_alerts_table(all_alerts)

    if output:
        with open(output, "w") as fh:
            json.dump(all_alerts, fh, indent=2, default=str)
        console.print(f"\nAlerts written to [green]{output}[/green]")

    cfg_out = cfg.get("output", {})
    out_file = output or cfg_out.get("file")
    if out_file and not output:
        with open(out_file, "w") as fh:
            json.dump(all_alerts, fh, indent=2, default=str)
        console.print(f"Alerts written to [green]{out_file}[/green]")


def _print_alerts_table(alerts):
    table = Table(title="TrailHunter Alerts", show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule", width=35)
    table.add_column("Actor", width=25)
    table.add_column("Event", width=30)
    table.add_column("Source IP", width=18)
    table.add_column("Time")

    severity_colors = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green"}
    for a in alerts:
        sev = a["severity"]
        color = severity_colors.get(sev, "white")
        table.add_row(
            f"[{color}]{sev.upper()}[/{color}]",
            a["rule_name"],
            a["actor"][:25],
            a["event_name"],
            a["source_ip"],
            a["event_time"],
        )
    console.print(table)


if __name__ == "__main__":
    main()
