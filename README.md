# Gmail Unsubscriber

**Find unwanted mailing lists in Gmail and choose which ones to leave.**

Version 3.1.3 · Testing · Windows and Linux · Python 3.10+

I built Gmail Unsubscriber to make dealing with newsletters and promotional email less repetitive. It checks your Gmail Inbox, groups mailing-list messages by sender, and lets you select the senders you want to unsubscribe from in one window.

**Start with a scan, review the list, then choose what to unsubscribe from.** Automatic unsubscribing is optional and is turned off by default.

[Download the ZIP](https://github.com/HaytamElbouhmidi/gmail-unsubscriber/archive/refs/heads/main.zip) · [Setup](#setup) · [Your first scan](#use-it) · [What the results mean](#results-and-limits)

## What can it help me do?

- Find mailing lists without opening each email separately.
- Search the results and choose the senders you want to leave.
- Include your Spam folder if you want to review it too.
- Stop a scan and continue it later without starting over.
- Save a results file that can be opened in a spreadsheet.

It sends unsubscribe requests, not guarantees. A sender may still need you to confirm removal on its website. The app does not delete emails, move them, or mark them as read.

**Before downloading:** This is a testing version, not a standalone installer. Python must be installed first. Windows has a double-click launcher. The Linux instructions below use a terminal to start the graphical app.

![Gmail Unsubscriber with sample sender results and scan settings](docs/images/overview.png)

*Screenshots use sample email records. They are captured from the actual Tkinter application without accessing Gmail. The appearance of native controls may differ between Windows and Linux.*

<details>
<summary>More screenshots</summary>

### Scan amount and folders

Choose 250, 500, 1,000, Custom, or Entire inbox. **Include Spam** also examines the Spam mailbox. In automatic mode, Spam results are for review only.

![Scan amount and optional Spam controls](docs/images/scan-amounts.png)

### Auto unsubscribe

Auto unsubscribe is off by default. When enabled, supported unsubscribe requests can be sent while the app checks your Inbox.

![Automatic unsubscribe option](docs/images/auto-unsubscribe.png)

### Search and outcome sorting

Search locally and sort by Sender, Subject, Latest email, or **Outcome**. Click the Outcome column to reverse the order and bring failures or successful submissions together.

![Sorting outcomes in the senders table](docs/images/search-and-sort.png)

### Scan progress and resume

The scan counts examined messages and keeps the progress bar updated. The **Resume scan** checkbox remembers earlier progress so an interrupted scan does not need to start over.

![Progress while scanning sample messages](docs/images/scan-progress.png)

![Stopped scan with resumable local progress](docs/images/resume.png)

On completion, the bar stays full. Complete means the scan finished, not that all removal requests succeeded.

![Completed scan with sample results](docs/images/scan-complete.png)

</details>

## Setup

### 1. Download and unpack the program

1. Click **Download the ZIP** above. A ZIP is a compressed folder containing all the program's files.
2. Extract the ZIP into a folder you can keep, such as a folder inside Documents.
3. Open the extracted folder. Keep its files together and do not run the app from inside the ZIP preview.

Choose the Windows or Linux instructions below, then continue to step 3.

### 2. Open the app on Windows

1. Install **Python 3.10 or newer** from [Python's Windows download page](https://www.python.org/downloads/windows/) if you do not already have it. Include **Tcl/Tk** and the **Python launcher**. Tcl/Tk supplies the app's windows and buttons.
2. Double-click **Gmail Unsubscriber (Standard Mode).pyw** in the extracted folder.
3. If the setup window appears, choose **Install and continue**. It downloads the extra Python components listed in `requirements.txt` into a separate environment for this app. Internet access is needed.
4. Wait for the main Gmail Unsubscriber window to open.

Scanning Gmail does not require administrator access. The **Standard Mode** file avoids that prompt. The alternative `Start Gmail Unsubscriber.cmd` starts the regular launcher, which can request administrator access. Use the Standard Mode file for ordinary use.

If double-clicking opens a text editor or nothing happens, Python's file association may not be set up. Open a terminal in the extracted folder and run:

```powershell
py "Gmail Unsubscriber (Standard Mode).pyw"
```

### 2. Open the app on Linux

You need Python 3.10 or newer, Tkinter for the window interface, and Python's `venv` and `pip` tools. Package names differ between Linux distributions.

1. Open a terminal in the extracted program folder.
2. Run these commands one at a time. They create a separate folder for the app's Python components, install them, and open the app:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python gmail_unsubscriber.py
```

3. On later visits, open a terminal in the same folder and run only:

```sh
.venv/bin/python gmail_unsubscriber.py
```

Do not add `sudo` to these commands. If setup reports that Tkinter, `venv`, or `pip` is missing, install the corresponding packages through your Linux distribution before retrying.

### 3. Create a Google app password

An **app password** is a separate code Google creates so this program can connect to your Gmail account. It is not your normal Google password, and it should be kept just as private.

1. Follow [Google's app-password instructions](https://support.google.com/accounts/answer/185833?hl=en). Your account needs **2-Step Verification**.
2. Create an app password for Gmail Unsubscriber. Some work, school, or protected accounts do not offer this option. If it is unavailable, follow Google's guidance or ask your account administrator rather than weakening your account security.
3. Enter your Gmail address and that app password in Gmail Unsubscriber. The **Google app passwords** button opens the account page.

This version uses app-password sign-in. Your ordinary Gmail password will not work. The app does not save the app password for your next session. You can revoke it in your Google Account when you no longer want the app to have access.

## Use it

### Your first scan

1. Enter your Gmail address and app password.
2. Leave **Auto unsubscribe while scanning** off so you can review everything first.
3. Choose **250** under **Scan amount** for a short first scan. Leave **Include Spam** off unless you want to review that folder too.
4. Click **Scan inbox** and wait for the results. You can use **Stop** to end the scan early.
5. Tick the boxes beside the senders you want to unsubscribe from. Highlighting a row is not the same as ticking its box.
6. Once scanning finishes or stops, click **Unsubscribe checked**.
7. Read the **Outcome** column to see what was sent and what still needs your attention.

You may tick boxes while scanning, but requests for those selections are sent only after the scan stops or finishes.

### Choose how much to scan

**Scan amount** offers **250**, **500**, **1,000**, **Custom**, and **Entire inbox**. Entire inbox asks for confirmation before checking all messages in the selected folders.

**Include Spam** adds Gmail's Spam folder to the scan. With a limited scan, the chosen number is shared between Inbox and Spam, and unused capacity can be taken from the other folder. Archived messages and Trash are not scanned.

A full progress bar means scanning finished. It does not mean every unsubscribe request succeeded.

### Optional automatic mode

Turn on **Auto unsubscribe while scanning** and choose **Scan + auto unsubscribe** only if you want supported Inbox requests sent without approving each sender individually.

**Spam results are always review-only in automatic mode.** To act on a Spam sender, use scan-only mode and tick that sender yourself. Contacting an unfamiliar sender can reveal that your address is active.

### Optional plain unsubscribe request emails

**Email sender if auto unsubscribe is unavailable** lets the app send a plain email from your Gmail account asking a mailing list to remove you when its supported unsubscribe method is unavailable or unsuccessful.

This is a separate option from automatic mode and is **off by default**. It is limited to identifiable Inbox mailing-list messages with a usable sender address. It is not used for Spam, ordinary personal messages, or common no-reply addresses.

A request email may reveal that your account is active and does not guarantee removal. If the email already includes an email-based unsubscribe instruction, that instruction takes priority. Website confirmation forms are not completed automatically.

### Resume an interrupted scan

Leave **Resume scan** checked to pick up after a stopped scan, a crash, or a restart.

1. Reopen the app and enter the same Gmail account.
2. Use the same scan amount, folder choices, and mode as before.
3. Start the scan. Earlier results are restored and already-processed messages are skipped.

Uncheck **Resume scan** to start a new scan. The separate request history still helps prevent accepted or uncertain requests from being sent again automatically.

If a request may have been delivered before an interruption, it can show **Outcome unknown**. The app does not automatically repeat it. **Stop** prevents later work but cannot take back an email or website request that has already been sent.

## Find, sort, and select senders

Each sender has a row showing the most recent scanned subject, date, number of mailing lists, and outcome.

- Use the search box to find sender names, addresses, subjects, or mailing-list identifiers, including earlier scanned subjects.
- Choose **Sender**, **Subject**, **Latest email**, or **Outcome** under **Sort by**. Click the Outcome heading or direction button to reverse the order.
- **Check shown** ticks only the visible search results. **Clear checks** removes all selections.
- Checked senders stay checked even when a search or sort hides them. Clear checks first if you want a completely new selection.
- Double-click a sender or choose **View details** to see its mailing lists, destination links, and individual results.

Search and sorting happen on your computer and do not send extra requests to Gmail. Dates use the email's Date header, displayed in your local time. Unknown dates appear at the bottom when sorting by date.

## Results and limits

Common results include:

| Outcome | What it means |
| --- | --- |
| **Request accepted** | The sender's website accepted the unsubscribe request. It does not prove your address has been removed yet. |
| **Email submitted** | Gmail accepted the outgoing unsubscribe email. The mailing list still needs to act on it. |
| **Manual action required** | You need to use the sender's confirmation page or another method yourself. The app has not completed that step. |
| **Failed** | The attempt did not complete successfully. Check View details for the reason. |
| **Blocked** | The app would not attempt an action because a required safety check did not pass. |
| **Outcome unknown** | The request may have been delivered, but no definite result was received. It will not be repeated automatically. |
| **Mixed outcomes** | The same sender has more than one mailing list or request with different results. |

The app supports certain one-click website requests and email-based unsubscribe instructions. It cannot complete every publisher's process or guarantee that future messages will stop.

Use **Export results** to save a CSV file, a table that spreadsheet programs can open, or enable automatic export. Results can contain private email addresses and personalized unsubscribe links. Do not upload these files to GitHub or share them publicly.

## Problems?

- **Nothing opens:** Extract the complete ZIP and keep all files from the same version together. Check that Python and Tkinter are installed.
- **Gmail authentication failed:** Check the Gmail address and use a Google app password, not your normal password. If you changed your Google password, you may need a new app password.
- **The connection test passes but sign-in fails:** **Test connection** checks whether the network connection works. It does not validate your Gmail address or password.
- **A scan stops after repeated errors:** Read the Activity log. Saved progress is retained so you can try continuing with the same settings.
- **A request needs manual action:** For a sender you recognize, check Gmail's own unsubscribe option or the original email. Do not bypass a warning just to make the app submit a request.

When reporting a problem, copy the relevant error after removing email addresses, passwords, private links, and unsubscribe tokens. Do not attach your scan-history database or exported results.

## Privacy and saved progress

The app stores scan progress and request results locally on your computer. It does **not** save your Gmail app password or email bodies. It does save some email details and may save personalized unsubscribe links.

That history file is **not encrypted**. Keep your Windows or Linux account protected and do not upload the history file to this repository. Deleting it removes the record used to avoid sending the same requests again.

## Technical details

You do not need this section for everyday use. It explains the safeguards, saved-history locations, and diagnostic tools.

<details>
<summary>Show technical reference</summary>

### Supported unsubscribe methods

The app handles supported HTTPS one-click unsubscribe requests and `mailto:` addresses in the `List-Unsubscribe` header. HTTPS one-click submission requires DKIM verification, an email-signature check. Web confirmation pages are flagged as **Manual action required** and are not opened or completed automatically.

The optional direct-email fallback requires an Inbox mailing-list message with a `List-ID`, `List-Unsubscribe`, or list/bulk `Precedence` header and a usable sender address.

### Windows DNS fallback

On Windows, if Python DNS queries for DKIM TXT keys time out, the app retries the lookup using the built-in Windows `Resolve-DnsName` command. This uses the system DNS configuration, not a hardcoded public DNS provider. If native DNS succeeds, subsequent DKIM lookups in that scan prefer the Windows resolver. The lookup is bounded, responds to Stop, and accepts exactly one TXT record for a signing key. A successful key lookup does not count as DKIM verification: the cryptographic signature must still pass before a POST is sent. Only one-minute per-scan key caching is used. This DNS cache does not write keys or messages to disk. If the key cannot be verified, the request stays manual. Windows PowerShell is required for this DNS fallback. You can check both DNS paths using `python diagnose_dkim_dns.py` from the application directory.

### Local scan history

Scan progress is kept in a local SQLite database, a file stored on your computer rather than in the downloaded program folder:

| System | Location |
| --- | --- |
| Windows, new database | `%USERPROFILE%\.gmail-unsubscriber\progress.sqlite3` |
| Windows, existing legacy database | `%LOCALAPPDATA%\gmail-unsubscriber\progress.sqlite3` |
| Linux | `${XDG_STATE_HOME:-~/.local/state}/gmail-unsubscriber/progress.sqlite3` |

On Windows, new scan-history databases are stored under the user-profile directory to avoid AppData write redirection. If the earlier AppData database already exists, the application **continues using that exact database** to preserve saved progress and prevent resending requests. It does not silently start a different database when an existing database cannot be opened. If a database error occurs, use `python diagnose_history.py` from the application folder to check both Windows paths. This command checks directory write access without reading Gmail or changing your saved scan history.

It saves mailbox UIDs, header metadata, scan configuration, request results, and a per-account delivery ledger. It does not store your Gmail app password or email bodies. The database is **not encrypted** and may contain private unsubscribe URLs or tokens. Keep it private and never upload it to your repository.

Resuming prevents repeated scanning of checkpointed messages. Requests are reserved in the ledger before delivery to limit duplicate submissions even if the program exits suddenly. A request without a definitive response stays uncertain. Removing the database also removes this protection and should only be done intentionally with the application closed.

### Why an automatic one-click request may require manual action

A valid one-click POST requires a DKIM signature covering both `List-Unsubscribe` and `List-Unsubscribe-Post` (RFC 8058). A failed or unavailable DKIM check blocks the POST. The app reports specific causes, such as a missing DNS signing key, a DNS timeout, a cryptographic signature mismatch, or a verification-library exception. It does not bypass DKIM, automatically retry a potentially sent request, or assume that a sender removed an address.

A message can show `dkim=pass` in Gmail's original-message view while failing one-click validation if its passing signature does not cover both unsubscribe headers. Older messages may also refer to signing keys no longer published in DNS. For known senders, check Gmail's built-in unsubscribe option or use the unsubscribe control in the original email. Do not paste personalized unsubscribe tokens into public bug reports.

The app checks mailbox UIDVALIDITY when resuming so a mailbox reset will not mix saved message identifiers with current messages. Mailbox reads use bounded retry and reconnect handling. Repeated failures can stop the scan while keeping its progress.

</details>

## Tests

Install requirements and run:

```sh
python -m unittest discover -v
```

GUI tests require a desktop session. On Linux with Xvfb:

```sh
xvfb-run -a python -m unittest discover -v
```

To refresh these README screenshots from the running application with synthetic data, install Pillow in your development environment and run:

```sh
python -m pip install pillow
python capture_readme.py
```

The tests mock Gmail, HTTP, SMTP, and DKIM verification. Offline tests cannot confirm that a live sender will accept an unsubscribe request.

## Support

Support my work on [Ko-fi](https://ko-fi.com/haytamelbouhmidi) or [Patreon](https://www.patreon.com/c/HaytamElbouhmidi).

## License

MIT. See [LICENSE](LICENSE).
