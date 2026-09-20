# Query-timeout check: SonarQube import probe

A **synthetic Mule 4 project** whose only purpose is to test how findings of a custom
static check get into SonarQube (Cloud and Server) through the
[generic issue import format](https://docs.sonarsource.com/sonarqube-server/latest/analyzing-source-code/importing-external-issues/generic-issue-import-format/)
(`sonar.externalIssuesReportPaths`).

There is **no real application here**: the flows are deliberately small, the SQL points at
generic tables (`orders`, `customers`, `report_jobs`, `batch_log`), nothing is built or
deployed, and every value of interest is either a placeholder (`${db.query.timeout}`) or a
literal chosen to trigger a specific finding class.

The check itself lives in `tools/check-db-query-timeout.py`: it reports Mule Database
connector operations under `src/main/**` that carry no `queryTimeout` attribute, and in its
extended mode it also reports questionable values (`0`, non-`SECONDS` units, expressions).

## Layout

```text
.
├── README.md
├── .gitignore                      build/ and .scannerwork/
├── mule-artifact.json              {"minMuleVersion": "4.6.0"} - lets Sonar's MuleSoft analyzer recognise a Mule project
├── sonar-project.properties        sources / tests / externalIssuesReportPaths (no projectKey, no organization)
├── .github/workflows/sonar-import.yml
├── tools/
│   └── check-db-query-timeout.py   the checker (writes the generic issue report)
└── src/
    ├── main/mule/
    │   ├── orders-flow.xml         compliant: every operation has a timeout (holds the shared <db:config>)
    │   ├── customers-flow.xml      three operations without queryTimeout, one compliant
    │   ├── reports-flow.xml        timeouts present but questionable: "0" and MILLISECONDS
    │   └── nested/batch/
    │       └── cleanup-flow.xml    one operation without queryTimeout, two folders deep
    └── test/munit/
        └── customers-test-suite.xml  MUnit suite with a db:select without queryTimeout - must be ignored
```

All Mule XML files are well-formed (`xmllint --noout` clean) and use the real namespaces
(`http://www.mulesoft.org/schema/mule/core`, `http://www.mulesoft.org/schema/mule/db`).

## What the checker looks for

| Mode | Scope | Reported |
|---|---|---|
| default | the nine operations `db:select`, `db:insert`, `db:update`, `db:delete`, `db:bulk-insert`, `db:bulk-update`, `db:bulk-delete`, `db:stored-procedure`, `db:query-single` | **blocker**: the `queryTimeout` attribute is missing. Nothing else - a present attribute with any value passes. |
| `--extended` | the twelve elements that carry the attribute (default nine + `db:execute-ddl`, `db:execute-script`, `db:listener`) | **blocker**: missing, empty, or not a positive integer literal (`0` means "no timeout"); **blocker**: `queryTimeoutUnit` present and not `SECONDS` (sub-second units are rounded up by the connector, `MINUTES`/`HOURS`/`DAYS` are practically unbounded); **info**: value is a DataWeave expression `#[...]`, legal but not checkable statically. Placeholders `${...}` always pass. |
| `--extended --require-property` | as `--extended` | additionally **convention**: a hard-coded numeric literal (`queryTimeout="30"`) instead of a `${...}` property. |

Only `*.xml` under a `src/main` directory is scanned (recursively). `src/test/**` is never read,
so the MUnit suite in this repository contributes nothing.

## Expected findings

Line numbers refer to the opening tag of the operation. "-" means no finding in that mode.

| File:line | Element | `queryTimeout` / unit | default | `--extended` | `--extended --require-property` |
|---|---|---|---|---|---|
| `src/main/mule/orders-flow.xml:19` | `db:select` | `${db.query.timeout}` | - | - | - |
| `src/main/mule/orders-flow.xml:29` | `db:update` | `${db.query.timeout}` / `SECONDS` | - | - | - |
| `src/main/mule/orders-flow.xml:39` | `db:stored-procedure` | `30` | - | - | convention (hard-coded literal) |
| `src/main/mule/orders-flow.xml:48` | `db:query-single` | `#[vars.queryTimeout]` | - | info (expression) | info (expression) |
| `src/main/mule/customers-flow.xml:13` | `db:select` | missing | **blocker** | **blocker** | **blocker** |
| `src/main/mule/customers-flow.xml:22` | `db:insert` | missing | **blocker** | **blocker** | **blocker** |
| `src/main/mule/customers-flow.xml:31` | `db:execute-script` | missing | - (outside the nine-tag scope) | **blocker** | **blocker** |
| `src/main/mule/customers-flow.xml:39` | `db:update` | `${db.query.timeout}` | - | - | - |
| `src/main/mule/reports-flow.xml:13` | `db:select` | `0` | - | **blocker** (no effective timeout) | **blocker** (no effective timeout) |
| `src/main/mule/reports-flow.xml:23` | `db:bulk-update` | `500` / `MILLISECONDS` | - | **blocker** (unit) | **blocker** (unit) + convention (literal) |
| `src/main/mule/nested/batch/cleanup-flow.xml:19` | `db:bulk-delete` | missing | **blocker** | **blocker** | **blocker** |
| `src/test/munit/customers-test-suite.xml:35` | `db:select` | missing | not scanned | not scanned | not scanned |

Totals, as measured with the checker on this tree (4 files scanned in every mode):

| Mode | Findings | Breakdown | Exit code |
|---|---|---|---|
| default | **3** | 3 blocker | 1 (0 with `--warn-only`) |
| `--extended` | **7** | 6 blocker, 1 info | 1 |
| `--extended --require-property` | **9** | 6 blocker, 2 convention, 1 info | 1 |

`--require-property` on its own changes nothing (it only applies inside the extended scope).
The workflow asserts the **default** total (3) against the generated report and fails the job if
the number drifts, so any edit to the XML files must be mirrored in that assertion and in this table.

## Running the checker locally

```sh
# default scope + the generic issue report the workflow feeds to Sonar
python3 tools/check-db-query-timeout.py . --sonar-report build/sonar-report.json

# everything the check proposes beyond the default scope
python3 tools/check-db-query-timeout.py . --extended
python3 tools/check-db-query-timeout.py . --extended --require-property

# machine-readable, and GitHub annotations without failing the build
python3 tools/check-db-query-timeout.py . --extended --json
python3 tools/check-db-query-timeout.py . --github --warn-only
```

Exit codes: `0` clean, `1` blocker findings, `2` nothing scanned (a misconfigured path is an
error, not a pass). Only the Python standard library is used.

## How the workflow behaves

`.github/workflows/sonar-import.yml` runs on pushes to `main`, on pull requests and on manual
dispatch, with `permissions: contents: read`, in one job on `ubuntu-latest`:

1. Checkout with `fetch-depth: 0` (Sonar needs history for blame and new-code detection).
2. `python3 tools/check-db-query-timeout.py . --github --warn-only --sonar-report build/sonar-report.json`
   (annotations in the run, report on disk, never fails the job by itself).
3. The extended modes are run as `--json` into `build/` for information only.
4. **Self-check of the report** with `jq`: `rules` is a non-empty array with unique ids, every
   `issues[].ruleId` refers to a declared rule, no issue carries `severity` or `type` (those
   belong on the rule in the current format), every `filePath` exists in the checkout, and the
   issue count equals the expected default total (**3**). Any deviation fails the job and the
   count is printed either way.
5. `build/` is uploaded as the artifact `query-timeout-check`.
6. **Gate**: if `SONAR_TOKEN` (repository secret), `SONAR_ORGANIZATION` or `SONAR_PROJECT_KEY`
   (repository variables) is empty, the job prints a `::notice` naming what is missing and the
   scan steps are skipped. The job is still green - the check and the self-check already ran.
7. Otherwise `SonarSource/sonarqube-scan-action@v8` runs with
   `-Dsonar.organization=... -Dsonar.projectKey=...`; the scanner reads
   `sonar-project.properties`, imports `build/sonar-report.json` and prints
   `.scannerwork/report-task.txt` (analysis id and dashboard URL) at the end.
8. **Server-side assertion.** The job waits for the background task named in
   `report-task.txt`, then asks the server how many open issues of the rule
   `external_mule-static-checks:mule-db-query-timeout-missing` the project (or the pull
   request) holds, and fails unless that number equals the expected default total. This is
   the only reliable control: an issue whose `filePath` does not match an analysed file is
   dropped with an `INFO` line (`External issues ignored for N unknown files`), the analysis
   stays green, and any issue previously reported at that location is closed as fixed.

Because the scan is gated on the secret, pull requests from forks (where secrets are empty)
run the check but never attempt a scan.

Observed on SonarQube Community Build 26.9 with SonarScanner CLI 8.1 (the same generic format
and the same scanner engine as SonarQube Cloud): a valid report imports as
`Imported 3 issues in 2 files`; a report with `severity` on an issue, a rule without
`impacts`, or malformed JSON aborts the analysis before upload; a leading `./` in `filePath`
still matches; importing the same findings as `MAINTAINABILITY/LOW` leaves every rating at A,
importing them as `RELIABILITY/BLOCKER` drops the reliability rating to E.

## SonarQube Cloud setup

Everything below is configured on the GitHub repository and on the Sonar side; nothing in the
files has to change.

| Where | Name | Value |
|---|---|---|
| Repository **variable** | `SONAR_ORGANIZATION` | the organization key in SonarQube Cloud |
| Repository **variable** | `SONAR_PROJECT_KEY` | the project key of the Sonar project bound to this repository |
| Repository **secret** | `SONAR_TOKEN` | a token that may analyse that project (a project analysis token or a user token) |

And, on the Sonar project itself: **CI-based analysis must be selected, i.e. Automatic
Analysis switched off**, before the workflow's scan step runs for the first time. External
issue import is not available under Automatic Analysis, and a project that is analysed both
automatically and from CI makes the CI scan fail. Switch the mode first, then trigger the
workflow.

Once the scan has run, the imported findings appear in the project as issues of the external
rules declared in the report (they are counted in the metrics and in the quality gate like any
other issue, and can be accepted or marked false-positive from the UI).

### SonarQube Server instead of Cloud

The same workflow works against a self-hosted server with two changes: add the environment
variable `SONAR_HOST_URL` (repository variable or secret) to the scan step, and drop
`-Dsonar.organization=...` from `args` (servers have no organizations). Everything else,
including the report self-check and the generic issue format, is identical.
