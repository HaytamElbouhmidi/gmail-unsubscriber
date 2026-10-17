# Gmail Unsubscriber 3.1.0 Update

This update targets the exact version 3.0 source revision in my GitHub repository. The updater checks the original source and does not apply changes to a different revision.

## Applying the update

1. Clone or download the existing [gmail-unsubscriber](https://github.com/HaytamElbouhmidi/gmail-unsubscriber) repository.
2. Extract everything in the v3.1.0 update ZIP into the repository's top-level directory, beside `gmail_unsubscriber.py`. Preserve the `patch_parts` and `docs/images` folders.
3. Close Gmail Unsubscriber if it is running.
4. Run the following commands from the repository directory.

```sh
python upgrade_v3_1_0.py
python -m pip install -r requirements.txt
python -m unittest discover -v
```

The installer verifies the upstream source, checks the updated Python syntax, backs up the original source, and installs the revised `README.md`. The new history module and documentation images stay alongside the application.

On a Linux desktop without a display attached, GUI tests can use:

```sh
xvfb-run -a python -m unittest discover -v
```

## Updating GitHub

After reviewing the changed source and tests, run:

```sh
git add gmail_unsubscriber.py scan_history.py test_gmail_unsubscriber.py test_gui_launcher.py test_v3_1_0.py .gitignore README.md docs/images/v3.1-*.png capture_readme.py

git commit -m "feat: add Spam review, email fallback and scan resume v3.1.0"
git push
```

If desired, use `python capture_readme.py` with Pillow installed before committing to replace the included sample UI previews with screenshots from the actual application.

The `patch_parts` and upgrade scripts are release-update tooling. They can remain local, or be committed alongside the source for reproducibility. The `.gitignore` excludes the original source backup, local database files, and temporary Python artifacts.

## Scope

The additional Spam mailbox is read-only. Automatic unsubscribe and plain sender-directed email fallback are limited to INBOX. A Spam sender can still be selected and processed manually after a scan-only run.

The persistent ledger prefers an uncertain outcome to a duplicate send. It cannot independently confirm that a sender honored an unsubscribe request, and there is no live Gmail integration test included with this update.
