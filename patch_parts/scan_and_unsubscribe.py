def scan_and_unsubscribe(account: str, password: str, limit: int, guard: NetworkGuard,
                         ledger: dict[tuple[str, str, str], str],
                         emit: Callable[[str, Any], None], *, automatic: bool = True,
                         include_spam: bool = False, request_fallback: bool = False,
                         history: Any = None, resume: bool = False) -> None:
    """Read requested folders and checkpoint each processed UID before moving on."""
    if not isinstance(limit, int) or limit < 0:
        raise ValueError("The message limit must be a nonnegative integer. Zero means all messages.")
    seen: set[str] = set()
    attempted: set[tuple[str, str]] = set()
    consecutive_failures = 0
    stats = dict(total=0, checked=0, accepted=0, unknown=0, manual=0,
                 failed=0, duplicates=0, unreadable=0, found=0, automatic=int(automatic))
    settings = dict(limit=limit, automatic=automatic, include_spam=include_spam,
                    request_fallback=request_fallback)
    folders = ("INBOX", "SPAM") if include_spam else ("INBOX",)
    emit("progress", ProgressUpdate(0, None, "Connecting to Gmail and loading message lists..."))
    run_id = None
    completed_run = False
    try:
        if history is not None:
            ledger.update(history.load_ledger(account))
        restored = history.latest_incomplete(account, settings) if history is not None and resume else None
        with ExitStack() as stack:
            boxes = {folder: stack.enter_context(RecoveringInbox(account, password, guard, emit, folder=folder))
                     for folder in folders}
            if restored:
                run_id, snapshot, stats = restored
                emit("run_id", run_id)
                for item in snapshot:
                    boxes[item["folder"]].validity = str(item["validity"])
                records = history.checkpoints(run_id)
                seen = history.seen_keys(run_id)
                prior_outcomes = history.outcomes(run_id)
                attempted = {(result.method, result.target) for result in prior_outcomes
                             if result.method in {"POST", "MAILTO", "REQUEST"} and result.status == "Failed"}
                emit("log", f"Resuming saved scan. {len(records):,} messages already checked.")
                for (folder, uid), (info, candidate, unreadable) in records.items():
                    guard.check()
                    if info is not None:
                        emit("message", info)
                    if candidate is not None:
                        emit("candidate", candidate)
                        entry = ledger.get((account.casefold(), "ENTRY", candidate.key))
                        if entry in UNCERTAIN_STATUSES and not any(
                            r.candidate.key == candidate.key for r in prior_outcomes):
                            emit("entry_status", (candidate, "Outcome unknown"))
                for result in prior_outcomes:
                    guard.check()
                    emit("result", result)
            else:
                all_ids = {folder: boxes[folder].message_ids(0 if include_spam else limit)
                           for folder in folders}
                if include_spam and limit:
                    inbox_ids = all_ids["INBOX"]
                    spam_ids = all_ids["SPAM"]
                    inbox_count = min(len(inbox_ids), (limit + 1) // 2)
                    spam_count = min(len(spam_ids), limit // 2)
                    remaining = limit - inbox_count - spam_count
                    if remaining:
                        take = min(remaining, len(inbox_ids) - inbox_count)
                        inbox_count += take
                        remaining -= take
                    if remaining:
                        spam_count += min(remaining, len(spam_ids) - spam_count)
                    all_ids["INBOX"] = inbox_ids[:inbox_count]
                    all_ids["SPAM"] = spam_ids[:spam_count]
                snapshot = [{"folder": folder, "validity": str(boxes[folder].validity),
                             "uids": all_ids[folder]} for folder in folders]
                stats["total"] = sum(len(item["uids"]) for item in snapshot)
                records = {}
                if history is not None:
                    run_id = history.new_run(account, settings, snapshot, stats)
                    emit("run_id", run_id)
            total = sum(len(item["uids"]) for item in snapshot)
            stats["total"] = total
            emit("progress", ProgressUpdate(stats["checked"], total, "Message list loaded. Starting scan..."))
            names = "INBOX + Spam" if include_spam else "INBOX"
            mode = "Auto unsubscribe enabled" if automatic else "Scan only"
            emit("log", f"{mode}. {total:,} messages from {names}. No messages will be moved or marked as read.")
            if include_spam and automatic:
                emit("log", "Spam is scanned for review only. No automatic requests are sent to Spam senders.")
            if request_fallback:
                emit("log", "Sender-directed email fallback enabled for identifiable mailing lists in INBOX only.")
            for item in snapshot:
                folder = item["folder"]
                inbox = boxes[folder]
                ids = item["uids"]
                for uid in ids:
                    if (folder, uid) in records:
                        continue
                    guard.check()
                    info = None
                    candidate = None
                    unreadable = False
                    emit("progress", ProgressUpdate(stats["checked"], total,
                         f"Reading {folder} UID {uid}. {stats['checked']:,}/{total:,} checked..."))
                    checkpoint_ok = True
                    try:
                        try:
                            raw = inbox.headers(uid)
                        except (MessageFetchError, OversizedLiteral) as exc:
                            unreadable = True
                            stats["unreadable"] += 1
                            consecutive_failures += 1
                            emit("log", f"SKIPPED {folder} UID {uid}: {display_text(exc)}")
                            if consecutive_failures >= MAX_CONSECUTIVE_FETCH_FAILURES:
                                raise MailboxError(
                                    f"{consecutive_failures} consecutive messages could not be read. "
                                    "The saved checkpoint can be resumed later.") from exc
                            continue
                        consecutive_failures = 0
                        if raw is None:
                            unreadable = True
                            stats["unreadable"] += 1
                            emit("log", f"{folder} UID {uid} no longer exists. Skipped.")
                            continue
                        try:
                            info = parse_message_info(raw, uid, folder=folder)
                            emit("message", info)
                            candidate = parse_candidate(raw, uid, str(inbox.validity), folder=folder,
                                                        request_fallback=request_fallback and folder == "INBOX")
                        except (ValueError, UnicodeError) as exc:
                            unreadable = True
                            stats["unreadable"] += 1
                            emit("log", f"{folder} UID {uid}: invalid message headers. {display_text(exc)}")
                            continue
                        if candidate is None:
                            continue
                        emit("candidate", candidate)
                        if not automatic or folder == "SPAM":
                            if candidate.key in seen:
                                stats["duplicates"] += 1
                            else:
                                seen.add(candidate.key)
                                stats["found"] += 1
                            continue
                        list_key = subscription_key(candidate)
                        list_ledger_key = (account.casefold(), "LIST", list_key) if list_key else None
                        previous = ledger.get(list_ledger_key) if list_ledger_key else None
                        if candidate.key in seen or previous in SUCCESS_STATUSES | UNCERTAIN_STATUSES:
                            stats["duplicates"] += 1
                            if previous:
                                emit("entry_status", (candidate, "Outcome unknown" if previous in UNCERTAIN_STATUSES
                                                      else "Already submitted"))
                            continue
                        stats["found"] += 1
                        outcomes: list[Result] = []

                        def report(kind: str, payload: Any) -> None:
                            if kind == "result":
                                outcomes.append(payload)
                                if list_ledger_key and payload.status in SUCCESS_STATUSES | UNCERTAIN_STATUSES:
                                    ledger[list_ledger_key] = payload.status
                                if history is not None:
                                    history.record_result(account, run_id, payload)
                            emit(kind, payload)

                        def reserve(c: Candidate, target: Target) -> None:
                            if history is not None:
                                history.reserve(account, c, target, ledger)

                        def finalize(c: Candidate, target: Target, status: str) -> None:
                            if history is not None:
                                history.finalize(account, c, target, status, ledger)

                        try:
                            execute_candidate(candidate, account, password, guard, inbox.verification_message,
                                              attempted, ledger, report, before_send=reserve, after_send=finalize)
                        finally:
                            states = {result.status for result in outcomes}
                            unverified_post = any(r.method == "POST" and r.status == "Manual action required"
                                                  for r in outcomes)
                            if not unverified_post or states & (SUCCESS_STATUSES | UNCERTAIN_STATUSES):
                                seen.add(candidate.key)
                            if states & SUCCESS_STATUSES:
                                stats["accepted"] += 1
                            elif states & UNCERTAIN_STATUSES:
                                stats["unknown"] += 1
                            elif "Already submitted" in states:
                                stats["duplicates"] += 1
                            elif "Manual action required" in states:
                                stats["manual"] += 1
                            elif states:
                                stats["failed"] += 1
                    except BaseException:
                        checkpoint_ok = False
                        raise
                    finally:
                        if checkpoint_ok:
                            stats["checked"] += 1
                            if history is not None:
                                history.checkpoint(run_id, folder, uid, info, candidate, unreadable, stats,
                                                   bool(candidate and candidate.key in seen))
                            emit("progress", ProgressUpdate(stats["checked"], total,
                                 f"Checked {stats['checked']:,}/{total:,} messages. {stats['found']:,} entries found."))
            completed_run = True
            emit("progress", ProgressUpdate(stats["checked"], total, "Finishing scan and updating results..."))
            emit("log", "Scan finished. Submitting a request does not independently confirm list removal." if automatic
                 else "Scan finished. Check senders, then choose Unsubscribe checked.")
    finally:
        if history is not None and run_id is not None:
            history.state(run_id, "complete" if completed_run else "interrupted")
        emit("summary", stats.copy())
        emit("log", "Run summary: " + run_summary(stats))
