# SecTestBed – SSH Brute‑Force Detection Test

SecTestBed is a lightweight, local‑only Python tool that simulates realistic SSH brute‑force attempts, injects fake events into a log file, detects them, and scores SSH‑brute detection coverage.

It is designed for Linux systems and is safe to run locally; no real network traffic or live SSH attacks are performed.

## What it does

SecTestBed performs the following operations:

- Generates realistic fake SSH brute‑force log entries (e.g., repeated failed password attempts).
- Injects these events into a local log file.
- Reads the log file and detects matching events based on keyword patterns.
- Computes and prints a structured scorecard that includes:
  - the number of fake events injected,
  - the number of events detected,
  - the success rate (percentage),
  - and execution time for both injection and detection phases.

This allows you to test how well your system or log analysis pipeline can detect SSH‑brute‑force‑like patterns without modifying or attacking any real service.

## Directory structure

The project is designed with a minimal file layout:

- `SecTestBed.py` – main script (single‑file, high‑efficiency implementation).
- `logs/` – directory where test log files are written.
- `README.md` – this documentation file.

## How to run it

To execute SecTestBed, follow these steps:

1. Open a terminal and navigate to the project directory:

   ```bash
   cd ~/SecTestBed
   ```

2. Run the script:

   ```bash
   python3 SecTestBed.py
   ```

3. Observe the console output, which shows:
   - how many fake SSH brute‑force events were injected,
   - how many of those events were detected,
   - the success rate (percentage),
   - and the time taken for injection and detection.

## Scorecard interpretation

After the test, SecTestBed displays the following metrics:

- **Injected** – the number of fake SSH brute‑force events created.
- **Detected** – the number of those events successfully identified by the detector.
- **Success rate** – the proportion of detected events relative to injected events, expressed as a percentage.
- **Execution time** – the time (in milliseconds) required for event injection and log detection.

Higher injection and detection counts combined with a high success rate indicate strong detection capability. Lower success rates or long detection times indicate areas for improvement in detection logic or system performance.

## Technical notes

- Detection is implemented using **keyword‑based pattern matching** rather than regular expressions, for simplicity and performance.
- Log lines are formatted to match standard Linux system log syntax (e.g., `auth.log`‑style lines).
- All operations are performed locally; no external dependencies beyond standard Python are required.
- The script is designed to be easily extended with additional test scenarios or detection rules.

## Why this is useful

SecTestBed provides a measurable, repeatable way to evaluate detection coverage for SSH‑brute‑force‑like events. It is useful for:

- Learning how detection and log analysis work together in a controlled environment.
- Testing and improving detection logic on a local machine.
- Demonstrating a security‑validation mindset in a portfolio or project context.

## Updating this repository on GitHub

After making changes to `SecTestBed.py` or adding files, update the remote repository with:

```bash
git add .
git commit -m "Update: improved SecTestBed"
git push
```

This keeps the GitHub repository synchronized with your local changes.

---








