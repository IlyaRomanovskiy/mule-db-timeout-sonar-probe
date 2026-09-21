#!/usr/bin/env python3
"""Report Mule DB operations without a query timeout.

Scans src/main/**/*.xml (recursively, all src/main roots found under ROOT).

DEFAULT = the agreed scope: the nine tags db:stored-procedure, db:select,
db:bulk-delete, db:bulk-insert, db:bulk-update, db:delete, db:insert, db:update and
db:query-single, and a violation is simply "the queryTimeout attribute is missing".
The severity ("error") means importance, not a requirement to block a merge.

--extended turns on everything proposed beyond that scope (three more elements,
zero/garbage values, the unit attribute). It must not be presented as "the agreed
check" unless those additions have been accepted.

Finding classes in --extended mode (same semantics as the equivalent SonarQube
XPath rules):

  blocker  queryTimeout missing, empty, or not a positive integer literal
           (0, 00, +0, 0.0, -1, 0x0 are all "no timeout" or garbage);
  blocker  queryTimeoutUnit present and not SECONDS. Two different traps:
           DAYS/HOURS/MINUTES make the timeout effectively unbounded, while
           sub-second units are not honoured as written — since connector
           1.11.0 (DBCON-318) "the connector rounds up values smaller than a
           second to avoid waiting indefinitely", so queryTimeout=30 with
           MILLISECONDS silently becomes 1 second instead of the intended 30
           (on connectors older than 1.11.0 the same value truncated to 0 =
           no timeout at all). Either way the effective timeout is not the one
           the author wrote, so the unit goes through review explicitly;
  info     value comes from a DataWeave expression #[...] — the parameter does
           support expressions, so this is legal code, but the effective value
           cannot be checked statically.

--require-property additionally reports a purely numeric literal: the recommended
form is queryTimeout="${...}" — a configuration property whose value lives in the
externalised configuration, so it can be tuned per application and per environment
without a rebuild.

--sonar-report PATH writes the same findings as a SonarQube generic-issue report
(the {"rules": [...], "issues": [...]} format read by sonar.externalIssuesReportPaths).
One ad-hoc rule per finding class:

  mule-db-query-timeout-missing              attribute missing (default and --extended)
  mule-db-query-timeout-no-effective-value   0 / garbage value (--extended)
  mule-db-query-timeout-unit                 queryTimeoutUnit other than SECONDS (--extended)
  mule-db-query-timeout-hardcoded            numeric literal (--extended --require-property), always LOW
  mule-db-query-timeout-expression           DataWeave expression (--extended), always INFO

The first three carry the impact given by --sonar-quality/--sonar-severity. Rules
never put "severity"/"type" on issues (the scanner rejects the deprecated fields),
the missing-rule is always present so an empty report still validates, and files
that failed to parse are left out of the report (they go to stderr instead).
filePath is relative to --sonar-base-dir (default: the current directory) — it must
equal the path the scanner sees relative to sonar.projectBaseDir, otherwise the
issue is silently dropped as an "unknown file".

Only the Python standard library (expat gives file:line for free).

Usage:
    python3 check-db-query-timeout.py [ROOT ...]              # agreed scope (default)
    python3 check-db-query-timeout.py --extended .           # + proposals beyond the agreed scope
    python3 check-db-query-timeout.py --require-property .   # + hardcoded values
    python3 check-db-query-timeout.py --json .               # machine-readable
    python3 check-db-query-timeout.py --warn-only .          # never fail the build
    python3 check-db-query-timeout.py --allow-empty .        # 0 files scanned is OK
    python3 check-db-query-timeout.py --since-ref origin/qa .  # only changed files
    python3 check-db-query-timeout.py --github .             # ::error/::warning annotations
    python3 check-db-query-timeout.py --sonar-report out/db-timeout.json .   # SonarQube generic-issue report
        [--sonar-quality MAINTAINABILITY|RELIABILITY|SECURITY]   # impact quality   (default MAINTAINABILITY)
        [--sonar-severity INFO|LOW|MEDIUM|HIGH|BLOCKER]           # impact severity  (default LOW)
        [--sonar-engine-id ID]                                    # rules' engineId  (default mule-static-checks)
        [--sonar-effort N]                                        # effortMinutes    (default 5)
        [--sonar-base-dir DIR]                                    # filePath base    (default: current directory)

    python3 check-db-query-timeout.py --help                    # this text
    (every value option also accepts the --option=value spelling)

Exit codes: 0 clean; 1 blocker findings, or a file that is not well-formed XML (it
could not be checked, and "not checked" is not "clean"); 2 misconfiguration — nothing
scanned (without --allow-empty), a root that is not a directory, an unknown option,
an invalid --sonar-* value, or a report path that cannot be written. --warn-only turns
1 into 0 but never 2. With --since-ref and no changed Mule XML the run is clean (0)
and the Sonar report, if requested, holds zero issues.
"""
import json
import os
import subprocess
import sys
import xml.parsers.expat

DB_NS = "http://www.mulesoft.org/schema/mule/db"

# 11 operations + the db:listener source — every element of the DB connector
# that carries queryTimeout/queryTimeoutUnit (verified against the connector's
# META-INF descriptor, db-connector 1.14/1.16). The ticket lists 9: execute-ddl,
# execute-script and listener are missing there.
OPERATIONS = {
    "select", "insert", "update", "delete",
    "bulk-insert", "bulk-update", "bulk-delete",
    "stored-procedure", "query-single",
    "execute-ddl", "execute-script",
    "listener",
}

# Exactly the nine tags of the agreed scope, checked exactly as worded there
# ("has queryTimeout attribute") — no unit check, no zero-value check. This is the
# default; everything beyond it is a proposal enabled by --extended and must be
# accepted before it is enforced.
TICKET_OPERATIONS = {
    "stored-procedure", "select", "bulk-delete", "bulk-insert", "bulk-update",
    "delete", "insert", "update", "query-single",
}

# The connector rounds sub-second units UP to whole seconds, so anything but
# SECONDS is either effectively infinite (DAYS/HOURS/MINUTES) or effectively
# zero (MILLISECONDS and below). MINUTES may be legitimate for long batch jobs —
# it is reported so that it goes through review explicitly.
ALLOWED_UNITS = {"SECONDS"}
# The full enumeration the connector accepts; anything else is not a unit at all.
TIME_UNITS = {"NANOSECONDS", "MICROSECONDS", "MILLISECONDS", "SECONDS", "MINUTES", "HOURS", "DAYS"}
# XML whitespace only — str.strip() would also eat U+00A0 and friends, so a value
# such as "&#160;30" would pass as 30 although the connector rejects it.
XML_WS = " \t\r\n"
# Attribute values are echoed into messages; cap them so a pathological value does
# not turn one finding into a multi-megabyte line.
MAX_ECHO = 120

# --- SonarQube generic-issue report (--sonar-report) --------------------------------
# One ad-hoc rule per finding class. The key order is the order rules are written.
SONAR_RULE_MISSING = "mule-db-query-timeout-missing"
SONAR_RULE_NO_VALUE = "mule-db-query-timeout-no-effective-value"
SONAR_RULE_UNIT = "mule-db-query-timeout-unit"
SONAR_RULE_HARDCODED = "mule-db-query-timeout-hardcoded"
SONAR_RULE_EXPRESSION = "mule-db-query-timeout-expression"

# id -> (name, description, cleanCodeAttribute, fixed impact severity or None =
# take --sonar-severity). Descriptions are deliberately neutral: they are shown in
# the SonarQube UI as the rule text.
SONAR_RULES = {
    SONAR_RULE_MISSING: (
        "Database operation must define queryTimeout",
        "A Mule Database connector operation without an explicit queryTimeout inherits "
        "the connector default 0, which means no timeout. A statement that hangs on the "
        "database side then holds its pooled connection indefinitely, and once the pool "
        "is exhausted the whole flow stops serving requests. Set queryTimeout on every "
        "operation, preferably from a configuration property.",
        "COMPLETE", None),
    SONAR_RULE_NO_VALUE: (
        "queryTimeout must be a positive integer",
        "The queryTimeout value is 0 or not a positive integer literal, so no effective "
        "timeout is applied and the operation behaves exactly as if the attribute were "
        "absent. Use a positive number of seconds, or a configuration property that "
        "resolves to one.",
        "LOGICAL", None),
    SONAR_RULE_UNIT: (
        "queryTimeoutUnit should stay SECONDS",
        "With a unit other than SECONDS the effective timeout is not the value written: "
        "DAYS, HOURS and MINUTES make it practically unbounded, while sub-second units are "
        "rounded up to one whole second by the connector (1.11.0 and later) or truncated "
        "to 0, i.e. no timeout, on older versions. Keep SECONDS unless the deviation has "
        "been reviewed deliberately.",
        "LOGICAL", None),
    SONAR_RULE_HARDCODED: (
        "queryTimeout should come from a configuration property",
        "The timeout is a numeric literal in the flow XML, so changing it requires a code "
        "change and a rebuild. Use a configuration property (${...}) so the value can be "
        "tuned per application and per environment without a rebuild.",
        "CONVENTIONAL", "LOW"),
    SONAR_RULE_EXPRESSION: (
        "queryTimeout is a DataWeave expression",
        "The timeout comes from a DataWeave expression, which is legal, but the effective "
        "value cannot be verified statically. Make sure the expression always evaluates "
        "to a positive number of seconds.",
        "CLEAR", "INFO"),
}
SONAR_QUALITIES = ("SECURITY", "RELIABILITY", "MAINTAINABILITY")
SONAR_SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "BLOCKER")
SONAR_DEFAULTS = {
    "--sonar-quality": "MAINTAINABILITY",
    "--sonar-severity": "LOW",
    "--sonar-engine-id": "mule-static-checks",
    "--sonar-effort": "5",
    "--sonar-base-dir": ".",
}
# Options that consume the next argument (everything else starting with -- is a flag).
VALUE_OPTIONS = ("--since-ref", "--sonar-report") + tuple(SONAR_DEFAULTS)
# Every option the tool understands. Anything else starting with -- is a typo
# (e.g. --extendd), and a typo must not silently run a narrower check.
KNOWN_OPTIONS = frozenset(
    ("--extended", "--require-property", "--json", "--warn-only", "--allow-empty",
     "--github", "--help", "-h") + VALUE_OPTIONS)

# The keys of a finding as emitted by --json and consumed by the text output. The
# internal "rule" key (the Sonar rule id of the finding class) is never printed.
FINDING_KEYS = ("file", "line", "operation", "queryTimeout", "queryTimeoutUnit",
                "severity", "reason")


def _short(value):
    """An attribute value as it is echoed into messages: capped at MAX_ECHO characters."""
    return value if len(value) <= MAX_ECHO else value[:MAX_ECHO] + "…(%d chars)" % len(value)


def _is_placeholder(value):
    return value.startswith("${")


def _is_expression(value):
    return value.startswith("#[")


def _positive_int_literal(value):
    """True only for a plain positive integer: '30' yes, '0'/'00'/'+0'/'0.0'/'-1'/'0x0' no.

    isascii() first: str.isdigit() accepts superscripts and other Unicode digits
    ('²'), which int() then rejects with ValueError."""
    return value.isascii() and value.isdigit() and int(value) >= 1


def scan_file(path, require_property=False, ticket_strict=False):
    findings = []
    parser = xml.parsers.expat.ParserCreate(namespace_separator="\x01")
    wanted = TICKET_OPERATIONS if ticket_strict else OPERATIONS

    def start_element(name, attrs):
        if "\x01" not in name:
            return
        ns, local = name.split("\x01", 1)
        if ns != DB_NS or local not in wanted:
            return

        line = parser.CurrentLineNumber
        op = "db:" + local
        present = "queryTimeout" in attrs
        unit_present = "queryTimeoutUnit" in attrs
        timeout = (attrs.get("queryTimeout") or "").strip(XML_WS)
        unit = (attrs.get("queryTimeoutUnit") or "").strip(XML_WS)

        def add(severity, reason, rule):
            findings.append({
                "file": path, "line": line, "operation": op,
                "queryTimeout": timeout or None, "queryTimeoutUnit": unit or None,
                "severity": severity, "reason": reason, "rule": rule,
            })

        if ticket_strict:
            # The ticket's own wording: the attribute is either there or it is not.
            # A present-but-blank attribute is reported too (it configures nothing),
            # under its own wording so the two cases stay distinguishable.
            if not present:
                add("blocker", "queryTimeout attribute is missing", SONAR_RULE_MISSING)
            elif timeout == "":
                add("blocker", "queryTimeout is present but empty — no effective timeout",
                    SONAR_RULE_NO_VALUE)
            return

        if _is_placeholder(timeout):
            pass                                    # a configuration property — fine
        elif _is_expression(timeout):
            add("info", "queryTimeout is a DataWeave expression — value cannot be "
                        "verified statically", SONAR_RULE_EXPRESSION)
        elif _positive_int_literal(timeout):
            if require_property:
                add("convention", 'queryTimeout="%s" is hardcoded — use a '
                                  "configuration property (${...}) so the value can be "
                                  "tuned per environment without a rebuild" % timeout,
                    SONAR_RULE_HARDCODED)
        elif not present:
            add("blocker", "queryTimeout is missing", SONAR_RULE_MISSING)
        elif timeout == "":
            add("blocker", "queryTimeout is present but empty — no effective timeout",
                SONAR_RULE_NO_VALUE)
        else:
            add("blocker", 'queryTimeout="%s" is not a positive integer — no effective '
                           "timeout" % _short(timeout), SONAR_RULE_NO_VALUE)

        if unit_present and not _is_placeholder(unit):
            if _is_expression(unit):
                add("info", "queryTimeoutUnit is a DataWeave expression — unit cannot be "
                            "verified statically", SONAR_RULE_EXPRESSION)
            elif unit == "":
                add("blocker", "queryTimeoutUnit is present but empty — no valid unit",
                    SONAR_RULE_UNIT)
            elif unit not in TIME_UNITS:
                add("blocker", 'queryTimeoutUnit="%s" is not a valid unit — expected SECONDS'
                               % _short(unit), SONAR_RULE_UNIT)
            elif unit not in ALLOWED_UNITS:
                add("blocker", 'queryTimeoutUnit="%s" — the effective timeout is not the '
                               "value written: DAYS/HOURS/MINUTES make it practically "
                               "unbounded, and sub-second units are rounded up to a whole "
                               "second by the connector (1.11.0+, DBCON-318) or truncated to "
                               "0 on older versions. Keep SECONDS unless the deviation is "
                               "reviewed deliberately" % unit,
                    SONAR_RULE_UNIT)

    parser.StartElementHandler = start_element
    try:
        with open(path, "rb") as fh:
            parser.ParseFile(fh)
    except xml.parsers.expat.ExpatError as exc:
        # Whatever expat reported before the error is a partial picture of a file
        # that was NOT checked as a whole — drop it so that text, --json, --github
        # and the Sonar report all say the same thing: one UNPARSED entry, at the
        # line where the parser gave up.
        findings.clear()
        findings.append({
            "file": path, "line": getattr(exc, "lineno", 1) or 1, "operation": None,
            "queryTimeout": None, "queryTimeoutUnit": None,
            "severity": "unparsed", "reason": "not well-formed XML, not checked (%s)" % exc,
            "rule": None,
        })
    except OSError as exc:
        findings.append({
            "file": path, "line": 1, "operation": None,
            "queryTimeout": None, "queryTimeoutUnit": None,
            "severity": "unparsed", "reason": "cannot read file (%s)" % exc,
            "rule": None,
        })
    return findings


def collect(root):
    """Every *.xml under any src/main directory below root (skipping build output)."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "node_modules")]
        # The real location decides, not the spelling: a root of "." given from inside
        # src/main/mule must still count as being under src/main.
        parts = os.path.realpath(dirpath).replace(os.sep, "/").split("/")
        in_src_main = any(
            parts[i] == "src" and i + 1 < len(parts) and parts[i + 1] == "main"
            for i in range(len(parts))
        )
        if not in_src_main:
            continue
        for name in filenames:
            if name.endswith(".xml"):
                files.append(os.path.join(dirpath, name))
    return sorted(files)


def changed_files(ref, cwd):
    """Files changed vs ref in the repository that contains `cwd` (a scanned root);
    None when git cannot answer (then everything is scanned).

    git prints paths relative to the repository root, so they are anchored at
    `git rev-parse --show-toplevel`; -z keeps non-ASCII names intact (git would
    otherwise C-quote them and the file would silently be skipped)."""
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=cwd,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        out = subprocess.run(
            ["git", "diff", "-z", "--name-only", "--diff-filter=d", "%s...HEAD" % ref],
            cwd=cwd, capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return {os.path.realpath(os.path.join(top, p)) for p in out.split("\0") if p.strip()}


def _split_args(argv):
    """(flags, option values, positional roots). Options in VALUE_OPTIONS consume the
    next argument unless it is itself an option; an option without a value is
    recorded as a flag only (main() then reports it as misconfigured)."""
    flags, values, roots = set(), {}, []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("-") and arg != "-":
            # Every dash-prefixed token is an option (a typo such as -extended must not
            # silently become a root); --opt=value is accepted for CI YAML convenience.
            if arg.startswith("--") and "=" in arg:
                arg, _, inline = arg.partition("=")
                flags.add(arg)
                values[arg] = inline
            else:
                flags.add(arg)
                if (arg in VALUE_OPTIONS and i + 1 < len(argv)
                        and not argv[i + 1].startswith("-")):
                    values[arg] = argv[i + 1]
                    i += 1
        else:
            roots.append(arg)
        i += 1
    return flags, values, roots


def _sonar_message(f):
    """Short, specific issue text for the SonarQube UI (the --json reason stays as is)."""
    op, rule = f["operation"], f["rule"]
    if rule == SONAR_RULE_MISSING:
        return "%s has no queryTimeout — the connector default 0 means no timeout." % op
    if rule == SONAR_RULE_NO_VALUE:
        if not f["queryTimeout"]:
            return "%s has an empty queryTimeout — no effective timeout." % op
        return ('%s has queryTimeout="%s", which is not a positive integer — no effective '
                "timeout." % (op, _short(f["queryTimeout"])))
    if rule == SONAR_RULE_UNIT:
        if not f["queryTimeoutUnit"]:
            return "%s has an empty queryTimeoutUnit — no valid unit." % op
        if f["queryTimeoutUnit"] not in TIME_UNITS:
            return ('%s has queryTimeoutUnit="%s", which is not a valid unit — use SECONDS.'
                    % (op, _short(f["queryTimeoutUnit"])))
        return ('%s has queryTimeoutUnit="%s" — the effective timeout is not the value '
                "written; keep SECONDS." % (op, f["queryTimeoutUnit"]))
    if rule == SONAR_RULE_HARDCODED:
        return ('%s has a hardcoded queryTimeout="%s" — use a configuration property '
                "(${...}) so the value can be tuned per environment without a rebuild."
                % (op, _short(f["queryTimeout"])))
    if f["operation"] and f["queryTimeoutUnit"] and _is_expression(f["queryTimeoutUnit"]) \
            and not _is_expression(f["queryTimeout"] or ""):
        return ("%s takes queryTimeoutUnit from a DataWeave expression — the unit cannot "
                "be verified statically." % op)
    return ("%s takes queryTimeout from a DataWeave expression — the effective value "
            "cannot be verified statically." % op)


def build_sonar_report(findings, base_dir, engine_id, quality, severity, effort):
    """Generic-issue report dict + the number of issues whose filePath escapes base_dir.

    Files that failed to parse are skipped entirely: expat reports the elements it saw
    before the error, but the file as a whole was not checked, so a partial picture
    would only mislead (the file is named on stderr instead). rules[] carries every
    rule an issue references plus the missing-rule, always, so a report with zero
    issues is still a valid CCT report.
    """
    # realpath, not abspath: on macOS /tmp is a symlink to /private/tmp, and a root
    # given through one spelling with a base dir given through the other must still
    # produce a repo-relative path.
    base = os.path.realpath(base_dir)
    unparsed = {f["file"] for f in findings if f["severity"] == "unparsed"}
    issues, used, outside = [], [], 0
    for f in findings:
        if not f["rule"] or f["file"] in unparsed:
            continue
        # Resolve the directory, keep the file name: a symlinked FILE under src/main is
        # indexed by the scanner under its own name, not under its target's.
        real = os.path.join(os.path.realpath(os.path.dirname(f["file"])),
                            os.path.basename(f["file"]))
        rel = os.path.relpath(real, base).replace(os.sep, "/")
        if rel.startswith("../"):
            outside += 1
        issues.append({
            "ruleId": f["rule"],
            "effortMinutes": effort,
            "primaryLocation": {
                "message": _sonar_message(f),
                "filePath": rel,
                "textRange": {"startLine": f["line"]},
            },
        })
        if f["rule"] not in used:
            used.append(f["rule"])
    rules = []
    for rule_id, (name, description, attribute, fixed_severity) in SONAR_RULES.items():
        if rule_id == SONAR_RULE_MISSING or rule_id in used:
            rules.append({
                "id": rule_id,
                "name": name,
                "description": description,
                "engineId": engine_id,
                "cleanCodeAttribute": attribute,
                "impacts": [{"softwareQuality": quality,
                             "severity": fixed_severity or severity}],
            })
    return {"rules": rules, "issues": issues}, outside


def write_sonar_report(path, report):
    """Write atomically (temp file + rename) so a concurrent reader never sees a
    truncated report. Raises OSError on any I/O problem; main() turns it into exit 2."""
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp-%d" % os.getpid()
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _gh_prop(value):
    """Escape a workflow-command property value (file=) per GitHub's grammar."""
    return (str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            .replace(":", "%3A").replace(",", "%2C"))


def _gh_msg(value):
    """Escape a workflow-command message per GitHub's grammar."""
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main(argv):
    flags, values, roots = _split_args(argv)
    roots = roots or ["."]
    since_ref = values.get("--since-ref")
    if "--help" in flags or "-h" in flags:
        print(__doc__)
        return 0

    warn_only = "--warn-only" in flags
    as_json = "--json" in flags
    require_property = "--require-property" in flags
    # Default = the agreed scope: nine tags and attribute presence only. Extensions
    # are opt-in via --extended.
    ticket_strict = "--extended" not in flags
    allow_empty = "--allow-empty" in flags
    gh = "--github" in flags

    # --sonar-* options: validated up front, a bad value is a misconfiguration (exit 2)
    # exactly like a path that scans nothing.
    def misconfigured(msg):
        # In --json mode stdout is the data channel, so diagnostics go to stderr.
        print(("::error::" + msg) if gh else ("ERROR: " + msg),
              file=sys.stderr if as_json else sys.stdout)
        return 2

    unknown = sorted(flags - KNOWN_OPTIONS)
    if unknown:
        return misconfigured("unknown option(s): %s. Known: %s"
                             % (" ".join(unknown), " ".join(sorted(KNOWN_OPTIONS))))

    if "--since-ref" in flags and not since_ref:
        return misconfigured("--since-ref requires a git ref.")
    sonar_report = values.get("--sonar-report")
    if "--sonar-report" in flags and not sonar_report:
        return misconfigured("--sonar-report requires a file path.")
    for opt in SONAR_DEFAULTS:
        if opt in flags and opt not in values:
            return misconfigured("%s requires a value." % opt)
    sonar = {opt: values.get(opt, default) for opt, default in SONAR_DEFAULTS.items()}
    if sonar["--sonar-quality"] not in SONAR_QUALITIES:
        return misconfigured("--sonar-quality must be one of %s, got %r."
                             % ("|".join(SONAR_QUALITIES), sonar["--sonar-quality"]))
    if sonar["--sonar-severity"] not in SONAR_SEVERITIES:
        return misconfigured("--sonar-severity must be one of %s, got %r."
                             % ("|".join(SONAR_SEVERITIES), sonar["--sonar-severity"]))
    sonar["--sonar-engine-id"] = sonar["--sonar-engine-id"].strip()
    if not sonar["--sonar-engine-id"]:
        return misconfigured("--sonar-engine-id must not be empty.")
    effort = sonar["--sonar-effort"]
    if not (effort.isascii() and effort.isdigit()) or int(effort) > 2147483647:
        return misconfigured("--sonar-effort must be a non-negative integer (max 2147483647), "
                             "got %r." % effort)
    if not os.path.isdir(sonar["--sonar-base-dir"]):
        return misconfigured("--sonar-base-dir %r is not a directory."
                             % sonar["--sonar-base-dir"])
    for root in roots:
        if not os.path.isdir(root):
            return misconfigured("root %r is not a directory." % root)
    if sonar_report and os.path.isdir(sonar_report):
        return misconfigured("--sonar-report %r is a directory, expected a file path."
                             % sonar_report)

    # Overlapping or repeated roots must not count a file twice.
    paths, seen = [], set()
    for root in roots:
        for p in collect(root):
            rp = os.path.realpath(p)
            if rp not in seen:
                seen.add(rp)
                paths.append(p)
    if sonar_report and os.path.realpath(sonar_report) in seen:
        return misconfigured("--sonar-report %r is one of the scanned XML files — refusing "
                             "to overwrite a source file." % sonar_report)
    found_any = bool(paths)

    skipped = 0
    if since_ref:
        changed, git_failed = set(), False
        for root in roots:
            c = changed_files(since_ref, root)
            if c is None:
                git_failed = True
                break
            changed |= c
        if git_failed:
            msg = "--since-ref %s: git diff failed, scanning everything" % since_ref
            print(("::warning::" if gh else "WARNING: ") + msg,
                  file=sys.stderr if as_json else sys.stdout)
        else:
            before = len(paths)
            paths = [p for p in paths if os.path.realpath(p) in changed]
            skipped = before - len(paths)

    findings = []
    for path in paths:
        findings.extend(scan_file(path, require_property, ticket_strict))

    blockers = [f for f in findings if f["severity"] == "blocker"]
    # A file that is not well-formed was not checked at all; "not checked" is not
    # "clean", so it fails the run like a blocker (unless --warn-only).
    unparsed = [f for f in findings if f["severity"] == "unparsed"]
    others = [f for f in findings if f["severity"] not in ("blocker", "unparsed")]

    if as_json:
        print(json.dumps({"scanned": len(paths), "skipped_unchanged": skipped,
                          "findings": [{k: f[k] for k in FINDING_KEYS} for f in findings]},
                         indent=2))
    else:
        for f in findings:
            line = "%s:%s: %s%s — %s" % (
                f["file"], f["line"], f["severity"].upper() + " ",
                f["operation"] or "file", f["reason"])
            if gh:
                level = "error" if f["severity"] == "blocker" else "warning"
                # normpath drops the "./" a root of "." leaves in front of the path;
                # GitHub matches annotation files against workspace-relative paths.
                print("::%s file=%s,line=%s::%s" % (
                    level, _gh_prop(os.path.normpath(f["file"])), f["line"],
                    _gh_msg(((f["operation"] + ": ") if f["operation"] else "") + f["reason"])))
            else:
                print(line)
        tail = ", %d other finding(s)" % len(others) if others else ""
        bad = ", %d file(s) not well-formed (not checked)" % len(unparsed) if unparsed else ""
        note = ", %d unchanged file(s) skipped" % skipped if skipped else ""
        print("\nScanned %d Mule XML file(s)%s; %d blocker(s)%s%s."
              % (len(paths), note, len(blockers), bad, tail))

    # The report is written only when the run is not about to fail with "nothing
    # scanned": a 0-issue report for a misconfigured path would import as a clean
    # project, which is the silent pass exit code 2 exists to prevent.
    if sonar_report and (found_any or allow_empty):
        report, outside = build_sonar_report(
            findings, sonar["--sonar-base-dir"], sonar["--sonar-engine-id"],
            sonar["--sonar-quality"], sonar["--sonar-severity"], int(sonar["--sonar-effort"]))
        try:
            write_sonar_report(sonar_report, report)
        except OSError as exc:
            return misconfigured("cannot write --sonar-report %r: %s" % (sonar_report, exc))
        for f in findings:
            if f["severity"] == "unparsed":
                print("WARNING: %s left out of the Sonar report — %s" % (f["file"], f["reason"]),
                      file=sys.stderr)
        if outside:
            print("WARNING: %d issue(s) point at files outside --sonar-base-dir %s — the "
                  "scanner will not match them" % (outside, sonar["--sonar-base-dir"]),
                  file=sys.stderr)
        # In --json mode stdout is the JSON document, so the one-liner goes to stderr.
        print("Sonar report: %s — %d issue(s), %d rule(s)"
              % (sonar_report, len(report["issues"]), len(report["rules"])),
              file=sys.stderr if as_json else sys.stdout)

    if not found_any and not allow_empty:
        # A misconfigured path must not look like a clean repository. (With --since-ref
        # and zero changed files the repository DID have Mule XML, so that is a clean
        # run, not this case.)
        return misconfigured(
            "Nothing scanned: no *.xml under any src/main directory below %s. "
            "Check the path, or pass --allow-empty for repositories that legitimately "
            "have no Mule sources." % ", ".join(roots))

    return 0 if (warn_only or not (blockers or unparsed)) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
