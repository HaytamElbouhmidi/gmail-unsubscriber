SORT_CHOICES = ("Sender", "Subject", "Latest email", "Outcome")
UTC_MIN = datetime.min.replace(tzinfo=timezone.utc)


def outcome_category(status: str) -> str:
    if status in SUCCESS_STATUSES | {"Already submitted", "Submitted"}:
        return "Successful"
    if status in {"Failed", "Blocked"}:
        return "Failed"
    if status in UNCERTAIN_STATUSES or status.startswith("Mixed") or status in {
            "Manual action required", "Needs attention", "Partial email submission"}:
        return "Needs attention"
    return "Pending"


def sorted_sender_rows(rows: list[SenderRow], sort_by: str, descending: bool,
                       status_for: Callable[[SenderRow], str] | None = None) -> list[SenderRow]:
    def text_key(row: SenderRow) -> tuple[str, str, str]:
        primary = row.latest.subject if sort_by == "Subject" else row.latest.sender_name
        return primary.casefold(), row.latest.sender_email.casefold(), row.key

    if sort_by == "Outcome" and status_for is not None:
        # Default order puts failed and uncertain results first.
        priority = {"Failed": 0, "Needs attention": 1, "Pending": 2, "Successful": 3}
        return sorted(rows, key=lambda row: (priority[outcome_category(status_for(row))],
                                              row.latest.sender_name.casefold(), row.key), reverse=descending)
    if sort_by != "Latest email":
        return sorted(rows, key=text_key, reverse=descending)
    dated = [row for row in rows if row.latest.sent_at is not None]
    unknown = [row for row in rows if row.latest.sent_at is None]
    dated.sort(key=lambda row: (row.latest.sender_name.casefold(), row.key))
    dated.sort(key=lambda row: row.latest.sent_at, reverse=descending)
    return dated + sorted(unknown, key=text_key)
