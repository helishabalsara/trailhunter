"""
Baselines CloudTrail account activity per actor to enable anomaly detection.
Tracks API call frequency per user/role and flags statistical deviations.
"""

import statistics
from collections import defaultdict
from typing import Dict, List


class ActivityBaseliner:
    def __init__(self, std_dev_threshold: float = 3.0, min_events: int = 10):
        self.std_dev_threshold = std_dev_threshold
        self.min_events = min_events
        # actor -> event_name -> list of hourly counts
        self._call_counts: Dict[str, Dict[str, List[int]]] = defaultdict(lambda: defaultdict(list))
        self._current_window: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def record(self, event: dict) -> None:
        actor = event.get("actor_username") or event.get("actor_arn", "unknown")
        action = event.get("event_name", "Unknown")
        self._current_window[actor][action] += 1

    def commit_window(self) -> None:
        """Call after each time window (e.g., hourly) to update baselines."""
        for actor, actions in self._current_window.items():
            for action, count in actions.items():
                self._call_counts[actor][action].append(count)
        self._current_window.clear()

    def is_anomalous(self, event: dict) -> bool:
        """Return True if this event represents anomalous activity vs baseline."""
        actor = event.get("actor_username") or event.get("actor_arn", "unknown")
        action = event.get("event_name", "Unknown")
        history = self._call_counts[actor][action]
        if len(history) < self.min_events:
            return False
        mean = statistics.mean(history)
        try:
            stdev = statistics.stdev(history)
        except statistics.StatisticsError:
            return False
        current = self._current_window[actor][action]
        if stdev == 0:
            return current > mean * 2
        z_score = (current - mean) / stdev
        return z_score > self.std_dev_threshold

    def get_summary(self) -> dict:
        summary = {}
        for actor, actions in self._call_counts.items():
            summary[actor] = {
                action: {
                    "call_count": sum(counts),
                    "windows_observed": len(counts),
                    "mean_per_window": round(statistics.mean(counts), 2) if counts else 0,
                }
                for action, counts in actions.items()
            }
        return summary
