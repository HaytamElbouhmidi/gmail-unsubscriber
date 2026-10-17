def request_email_target(message: Any, sender: str) -> Target | None:
    """Use a plain request only for identifiable mailing-list mail."""
    from urllib.parse import quote
    if len(message.get_all("From", [])) != 1:
        return None
    list_id = header_values(message, "List-ID")
    precedence = header_values(message, "Precedence")
    if not ((len(list_id) == 1 and list_id[0]) or
            (len(precedence) == 1 and precedence[0].casefold() in {"list", "bulk"})):
        return None
    try:
        address = validate_address(sender)
    except (ValueError, SafetyError):
        return None
    mailbox_name = address.split("@", 1)[0].casefold().replace(".", "").replace("-", "").replace("_", "")
    if any(word in mailbox_name for word in ("noreply", "donotreply", "bounce", "mailerdaemon", "postmaster")):
        return None
    subject = quote("Unsubscribe request", safe="")
    body = quote("Please remove me from this mailing list and stop sending these messages. Thank you.", safe="")
    return Target("REQUEST", f"mailto:{quote(address, safe='@')}?subject={subject}&body={body}",
                  "Plain unsubscribe request to the list sender. Removal is not independently confirmed.")


def parse_candidate(raw: bytes, uid: str, validity: str, *, folder: str = "INBOX",
                    request_fallback: bool = False) -> Candidate | None:
    message = BytesHeaderParser(policy=policy.compat32).parsebytes(raw)
    unsubscribe = header_values(message, "List-Unsubscribe")
    if not unsubscribe and not request_fallback:
        return None
    post = header_values(message, "List-Unsubscribe-Post")
    links = list(dict.fromkeys(re.findall(r"<([^<>]+)>", " ".join(unsubscribe))))
    name, address = parseaddr(decode_mime_header(message.get("From")))
    name = display_text(name or address or "Unknown sender")
    address = display_text(address)
    list_id = display_text(message.get("List-ID", ""))
    malformed_headers = (len(unsubscribe) > 1 or len(post) > 1 or len(links) > 16 or
                         len(message.get_all("From", [])) != 1)
    web_schemes = [link.split(":", 1)[0].lower() for link in links if ":" in link]
    one_click = (not malformed_headers and post == [POST_VALUE] and
                 web_schemes.count("https") == 1 and "http" not in web_schemes)
    targets: list[Target] = []
    if unsubscribe and not links:
        targets.append(Target("BLOCKED", "", "No supported angle-bracketed unsubscribe target."))
    for link in links[:16]:
        try:
            if malformed_headers:
                raise SafetyError("Duplicate From or unsubscribe headers, or too many targets. Manual inspection required.")
            scheme = link.split(":", 1)[0].lower()
            if scheme in {"https", "http"}:
                parsed = parse_web_url(link, https_only=False)
                if one_click and scheme == "https":
                    targets.append(Target("POST", parsed.url, "DKIM verification required before sending."))
                else:
                    targets.append(Target("MANUAL", parsed.url, "Review this webpage manually."))
            elif scheme == "mailto":
                parse_mailto(link)
                targets.append(Target("MAILTO", link, "Sends an email to the listed unsubscribe address."))
            else:
                raise SafetyError("Unsupported unsubscribe scheme.")
        except (ValueError, UnicodeError) as exc:
            targets.append(Target("BLOCKED", link, display_text(exc)))
    if request_fallback and folder == "INBOX" and not malformed_headers and not any(
            target.method == "MAILTO" for target in targets):
        plain_request = request_email_target(message, address)
        if plain_request is not None:
            targets.append(plain_request)
    if not targets:
        return None
    targets.sort(key=lambda target: {"POST": 0, "MAILTO": 1, "MANUAL": 2,
                                     "BLOCKED": 3, "REQUEST": 4}[target.method])
    fingerprint = hashlib.sha256(repr((unsubscribe, post)).encode("utf-8")).hexdigest()
    return Candidate(uid, validity, name, address, decode_mime_header(message.get("Subject")),
                     list_id, tuple(targets), fingerprint, parse_sent_date(message), folder)
