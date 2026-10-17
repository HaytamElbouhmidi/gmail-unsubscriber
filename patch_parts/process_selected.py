def process_selected(candidates: tuple[Candidate, ...], account: str, password: str,
                     guard: NetworkGuard, ledger: dict[tuple[str, str, str], str],
                     emit: Callable[[str, Any], None], *, history: Any = None,
                     run_id: int | None = None) -> None:
    """Process checked senders with mailbox-specific verification and durable outcomes."""
    attempted: set[tuple[str, str]] = set()
    seen: set[str] = set()
    completed_lists: set[str] = set()
    if history is not None:
        ledger.update(history.load_ledger(account))
    with ExitStack() as stack:
        boxes = {}
        for candidate in candidates:
            if candidate.folder not in boxes:
                boxes[candidate.folder] = stack.enter_context(
                    RecoveringInbox(account, password, guard, emit, folder=candidate.folder))

        def load(candidate: Candidate) -> bytes:
            box = boxes[candidate.folder]
            box._open()
            if any(item.validity != boxes[item.folder].validity for item in candidates
                   if boxes[item.folder].mail is not None):
                raise StaleScanError("A mailbox UIDVALIDITY changed. Run a fresh scan before sending.")
            return box.verification_message(candidate)

        completed = 0
        emit("progress", ProgressUpdate(0, len(candidates), "Preparing checked senders...", "entries"))
        for index, candidate in enumerate(candidates, 1):
            guard.check()
            emit("progress", ProgressUpdate(completed, len(candidates),
                 f"Processing checked entry {index:,}/{len(candidates):,}: {candidate.sender_name}", "entries"))
            try:
                list_key = subscription_key(candidate)
                ledger_key = (account.casefold(), "LIST", list_key) if list_key else None
                previous = ledger.get(ledger_key) if ledger_key else None
                if candidate.key in seen or previous in SUCCESS_STATUSES | UNCERTAIN_STATUSES:
                    if previous and list_key not in completed_lists:
                        completed_lists.add(list_key)
                        emit("result", Result(candidate, account, "ENTRY", "",
                             "Outcome unknown" if previous in UNCERTAIN_STATUSES else "Already submitted",
                             "This list has already been processed. No request repeated."))
                    completed = index
                    continue
                outcomes: list[Result] = []

                def report(kind: str, payload: Any) -> None:
                    if kind == "result":
                        outcomes.append(payload)
                        if ledger_key and payload.status in SUCCESS_STATUSES | UNCERTAIN_STATUSES:
                            ledger[ledger_key] = payload.status
                            completed_lists.add(list_key)
                        if history is not None:
                            history.record_result(account, run_id, payload)
                    emit(kind, payload)

                def reserve(c: Candidate, target: Target) -> None:
                    if history is not None:
                        history.reserve(account, c, target, ledger)

                def finalize(c: Candidate, target: Target, status: str) -> None:
                    if history is not None:
                        history.finalize(account, c, target, status, ledger)

                execute_candidate(candidate, account, password, guard, load, attempted, ledger,
                                  report, before_send=reserve, after_send=finalize)
                states = {result.status for result in outcomes}
                unverified_post = any(r.method == "POST" and r.status == "Manual action required" for r in outcomes)
                if not unverified_post or states & (SUCCESS_STATUSES | UNCERTAIN_STATUSES):
                    seen.add(candidate.key)
                completed = index
            finally:
                emit("progress", ProgressUpdate(completed, len(candidates),
                     "Updating checked-sender results...", "entries"))
    emit("log", "Checked senders processed. Accepted requests are not proof of completed removal.")
