#!/usr/bin/env python3
"""Read and triage comrade's Coverity Scan results.

Two sides, standard library only: the Connect SOAP API (v9) behind the Scan
defect viewer, and the mailbox that receives Scan's digests.

  covscan.py [--json] streams
  covscan.py [--json] snapshots
  covscan.py [--json] list [--scope current|last|all] [--third-party] [--all-triage]
  covscan.py [--json] show CID...
  covscan.py [--json] triage CID... --classification X [--action Y] [--owner O]
                      [--comment TEXT] [--store S]
  covscan.py [--json] history CID
  covscan.py [--json] fixed
  covscan.py [--json] components
  covscan.py [--json] mail poll | wait [--timeout S] | show UID [--raw] | done UID...

Environment: COVERITY_CONNECT_URL (default https://scan9.scan.coverity.com),
COVERITY_CONNECT_USER and COVERITY_CONNECT_KEY, COVERITY_SCAN_PROJECT (default
the origin remote's owner/repo), COVERITY_IMAP_URL (default
imaps://coverity@pidgin.makrotopia.org/, the path names the folder),
COVERITY_IMAP_PASSWORD (default the ~/.netrc entry for the host).
"""

import argparse
import email
import email.policy
import html.parser
import imaplib
import json
import netrc
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
NS_WSSE = ("http://docs.oasis-open.org/wss/2004/01/"
           "oasis-200401-wss-wssecurity-secext-1.0.xsd")
NS_V9 = "http://ws.coverity.com/v9"
PASSWORD_TEXT = ("http://docs.oasis-open.org/wss/2004/01/"
                 "oasis-200401-wss-username-token-profile-1.0#PasswordText")

# The front proxy of the Scan viewer refuses the Python default.
USER_AGENT = "covscan.py (https://github.com/dangowrt/comrade)"
PAGE_SIZE = 500
SCAN_SENDER = "scan-admin@coverity.com"
IDLE_SPAN = 25 * 60
COMPONENTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "coverity-components")
TRAILER = "Addresses-Coverity-ID"


class Fail(Exception):
    pass


def die(msg):
    raise Fail(msg)


def project_get(args):
    name = args.project or os.environ.get("COVERITY_SCAN_PROJECT")
    if name:
        return name
    try:
        url = subprocess.run(["git", "remote", "get-url", "origin"],
                             capture_output=True, text=True,
                             check=True).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        die("COVERITY_SCAN_PROJECT is not set and there is no origin remote")
    url = url.removesuffix(".git").rstrip("/")
    rest, _, repo = url.rpartition("/")
    owner = re.split(r"[/:]", rest)[-1]
    return f"{owner}/{repo}"


def xml_add(parent, name, value):
    if value is None:
        return
    if isinstance(value, list):
        for item in value:
            xml_add(parent, name, item)
        return
    elem = ET.SubElement(parent, name)
    if isinstance(value, dict):
        for k, v in value.items():
            xml_add(elem, k, v)
    elif isinstance(value, bool):
        elem.text = "true" if value else "false"
    else:
        elem.text = str(value)


def obj_from(elem):
    """An element as {tag: [child objects]}, a leaf as its text."""
    if len(elem) == 0:
        return elem.text or ""
    out = {}
    for child in elem:
        tag = child.tag.rpartition("}")[2]
        out.setdefault(tag, []).append(obj_from(child))
    return out


def get(obj, *path, default=None):
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return default
        obj = obj[key][0]
    return obj


def many(obj, key):
    if not isinstance(obj, dict):
        return []
    return obj.get(key, [])


class Connect:
    def __init__(self, url, user, key):
        self.url = url.rstrip("/")
        self.user = user
        self.key = key

    def envelope(self, op, children):
        ET.register_namespace("soapenv", NS_SOAP)
        ET.register_namespace("wsse", NS_WSSE)
        ET.register_namespace("v9", NS_V9)
        env = ET.Element(f"{{{NS_SOAP}}}Envelope")
        header = ET.SubElement(env, f"{{{NS_SOAP}}}Header")
        sec = ET.SubElement(header, f"{{{NS_WSSE}}}Security")
        sec.set(f"{{{NS_SOAP}}}mustUnderstand", "1")
        tok = ET.SubElement(sec, f"{{{NS_WSSE}}}UsernameToken")
        ET.SubElement(tok, f"{{{NS_WSSE}}}Username").text = self.user
        pw = ET.SubElement(tok, f"{{{NS_WSSE}}}Password")
        pw.set("Type", PASSWORD_TEXT)
        pw.text = self.key
        body = ET.SubElement(env, f"{{{NS_SOAP}}}Body")
        call = ET.SubElement(body, f"{{{NS_V9}}}{op}")
        for name, value in children.items():
            xml_add(call, name, value)
        return ET.tostring(env, encoding="utf-8", xml_declaration=True)

    def call(self, service, op, **children):
        req = urllib.request.Request(
            f"{self.url}/ws/v9/{service}", data=self.envelope(op, children),
            headers={"Content-Type": "text/xml; charset=utf-8",
                     "SOAPAction": '""', "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raw = e.read()
            fault = soap_fault(raw)
            if fault:
                die(f"{op}: {fault}")
            if e.code == 401:
                die(f"{op}: HTTP 401, the Connect credentials were refused")
            die(f"{op}: HTTP {e.code}")
        except urllib.error.URLError as e:
            die(f"{op}: {e.reason}")
        root = ET.fromstring(raw)
        fault = soap_fault(raw)
        if fault:
            die(f"{op}: {fault}")
        found = root.find(f".//{{{NS_V9}}}{op}Response")
        if found is None:
            die(f"{op}: no {op}Response in the reply")
        return [obj_from(r) for r in found.findall("return")]


def soap_fault(raw):
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None
    fault = root.find(f".//{{{NS_SOAP}}}Fault")
    if fault is None:
        return None
    text = fault.findtext("faultstring") or "SOAP fault"
    msg = fault.findtext(".//message")
    return f"{text}: {msg}" if msg else text


def connect_open():
    user = os.environ.get("COVERITY_CONNECT_USER")
    key = os.environ.get("COVERITY_CONNECT_KEY")
    if not user or not key:
        die("COVERITY_CONNECT_USER and COVERITY_CONNECT_KEY are not both set")
    url = os.environ.get("COVERITY_CONNECT_URL",
                         "https://scan9.scan.coverity.com")
    return Connect(url, user, key)


def project_info(conn, project):
    projects = conn.call("configurationservice", "getProjects",
                         filterSpec={"includeStreams": True,
                                     "namePattern": project})
    for p in projects:
        if get(p, "id", "name") != project:
            continue
        streams = many(p, "streams")
        if not streams:
            die(f"project {project} has no stream")
        s = streams[0]
        return {"project": project, "stream": get(s, "id", "name"),
                "triage_store": get(s, "triageStoreId", "name"),
                "component_map": get(s, "componentMapId", "name"),
                "streams": [get(x, "id", "name") for x in streams]}
    die(f"no project named {project} is visible to this user")


def description_parse(text):
    out = {}
    for m in re.finditer(r"(\w+)=(\S+)", text or ""):
        out[m.group(1)] = m.group(2)
    return out


def snapshots_all(conn, stream):
    ids = conn.call("configurationservice", "getSnapshotsForStream",
                    streamId={"name": stream})
    ids = [int(get(i, "id")) for i in ids]
    if not ids:
        return []
    infos = conn.call("configurationservice", "getSnapshotInformation",
                      snapshotIds=[{"id": i} for i in ids])
    snaps = []
    for s in infos:
        desc = get(s, "description", default="")
        fields = description_parse(desc)
        snaps.append({"id": int(get(s, "snapshotId", "id")),
                      "date": get(s, "dateCreated", default=""),
                      "description": desc,
                      "backend": fields.get("backend"),
                      "sha": fields.get("sha"),
                      "run": fields.get("run"),
                      "version": get(s, "sourceVersion", default=""),
                      "build_ok": int(get(s, "buildSuccessCount", default=0)),
                      "build_failed": int(get(s, "buildFailureCount",
                                              default=0))})
    snaps.sort(key=lambda s: (s["date"], s["id"]))
    return snaps


def snapshots_current(snaps):
    """The newest snapshot per backend, a snapshot without one under None."""
    newest = {}
    for s in snaps:
        newest[s["backend"]] = s
    return newest


def attrs_of(defect):
    out = {}
    for a in many(defect, "defectStateAttributeValues"):
        name = get(a, "attributeDefinitionId", "name")
        if name:
            out[name] = get(a, "attributeValueId", "name", default="")
    return out


def row_from(defect, rules):
    attrs = attrs_of(defect)
    path = get(defect, "filePathname", default="")
    return {"cid": int(get(defect, "cid")),
            "checker": get(defect, "checkerName", default=""),
            "type": get(defect, "displayType", default=""),
            "impact": get(defect, "displayImpact", default=""),
            "component": component_of(rules, path),
            "component_scan": get(defect, "componentName", default=""),
            "file": path,
            "function": get(defect, "functionDisplayName", default=""),
            "first_version": get(defect, "firstDetectedVersion",
                                 default=""),
            "last_version": get(defect, "lastDetectedVersion", default=""),
            "last_snapshot": int(get(defect, "lastDetectedSnapshotId",
                                     default=0)),
            "classification": attrs.get("Classification", ""),
            "action": attrs.get("Action", ""),
            "owner": attrs.get("Owner", ""),
            "backends": []}


def defects_page(conn, op, **fixed):
    start = 0
    while True:
        page = conn.call("defectservice", op,
                         **fixed,
                         pageSpec={"pageSize": PAGE_SIZE,
                                   "sortAscending": True,
                                   "startIndex": start})
        page = page[0] if page else {}
        defects = many(page, "mergedDefects")
        yield from defects
        total = int(get(page, "totalNumberOfRecords", default=0))
        start += len(defects)
        if not defects or start >= total:
            return


def defects_snapshot(conn, project, snapshot_id):
    return defects_page(conn, "getMergedDefectsForSnapshotScope",
                        projectId={"name": project}, filterSpec={},
                        snapshotScope={"showSelector": str(snapshot_id)})


def defects_project(conn, project):
    yield from defects_page(conn, "getMergedDefectsForProjectScope",
                            projectId={"name": project}, filterSpec={})


def defects_union(conn, project, snaps, rules):
    rows = {}
    for s in snaps:
        label = s["backend"] or f"snapshot {s['id']}"
        for d in defects_snapshot(conn, project, s["id"]):
            row = rows.setdefault(int(get(d, "cid")), row_from(d, rules))
            row["backends"].append(label)
    return rows


def triaged_away(row):
    return (row["classification"] in ("False Positive", "Intentional")
            or row["action"] == "Ignore")


def third_party(row):
    return row["component"].startswith("3rd-party")


def rules_load(path=COMPONENTS_FILE):
    rules = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            if "\t" not in line:
                die(f"{path}:{n}: expected pattern<TAB>component")
            pattern, component = line.split("\t", 1)
            rules.append((re.compile(pattern), pattern, component.strip()))
    return rules


def component_of(rules, path):
    for regex, _, component in rules:
        if regex.fullmatch(path):
            return component
    return ""


def git_claims():
    """CIDs named by Addresses-Coverity-ID trailers, cid -> [(sha, subject)]."""
    fmt = f"%H%x1f%s%x1f%(trailers:key={TRAILER},valueonly)%x1e"
    try:
        out = subprocess.run(["git", "log", f"--format={fmt}",
                              f"--grep={TRAILER}:"],
                             capture_output=True, text=True,
                             check=True).stdout
    except (subprocess.CalledProcessError, OSError):
        return {}
    claims = {}
    for rec in out.split("\x1e"):
        if "\x1f" not in rec:
            continue
        sha, subject, values = rec.strip("\n").split("\x1f", 2)
        for value in values.splitlines():
            m = re.match(r"\s*(\d+)", value)
            if m:
                claims.setdefault(int(m.group(1)), []).append(
                    (sha[:12], subject))
    return claims


def table(rows, headers):
    widths = [len(h) for h in headers]
    cells = [[str(c) for c in r] for r in rows]
    for r in cells:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers).rstrip())
    for r in cells:
        print(fmt.format(*r).rstrip())


def emit(args, data, text):
    if args.json:
        json.dump(data, sys.stdout, indent=2)
        print()
    else:
        text()


def cmd_streams(args):
    conn = connect_open()
    info = project_info(conn, project_get(args))

    def text():
        print(f"project: {info['project']}")
        for s in info["streams"]:
            print(f"stream:  {s}")
        print(f"triage store:  {info['triage_store']}")
        print(f"component map: {info['component_map']}")
    emit(args, info, text)


def cmd_snapshots(args):
    conn = connect_open()
    info = project_info(conn, project_get(args))
    snaps = snapshots_all(conn, info["stream"])
    current = snapshots_current(snaps)

    def text():
        rows = []
        for s in snaps:
            mark = "*" if current.get(s["backend"]) is s else ""
            rows.append([s["id"], s["date"][:19], s["backend"] or "-",
                         (s["sha"] or "-")[:12], s["run"] or "-",
                         f"{s['build_ok']}/{s['build_failed']}", mark,
                         s["version"]])
        table(rows, ["snapshot", "date", "backend", "sha", "run",
                     "ok/fail", "cur", "version"])
    emit(args, snaps, text)


def scope_rows(conn, info, args, rules):
    if args.scope == "all":
        rows = {}
        for d in defects_project(conn, info["project"]):
            rows[int(get(d, "cid"))] = row_from(d, rules)
        return rows, []
    snaps = snapshots_all(conn, info["stream"])
    if not snaps:
        return {}, []
    if args.scope == "last":
        chosen = [snaps[-1]]
    else:
        chosen = sorted(snapshots_current(snaps).values(),
                        key=lambda s: s["id"])
    return defects_union(conn, info["project"], chosen, rules), chosen


def cmd_list(args):
    conn = connect_open()
    rules = rules_load()
    info = project_info(conn, project_get(args))
    rows, snaps = scope_rows(conn, info, args, rules)
    kept = [r for r in rows.values()
            if args.all_triage or not triaged_away(r)]
    own = [r for r in kept if not third_party(r)]
    foreign = [r for r in kept if third_party(r)]
    for r in own + foreign:
        r["backends"] = sorted(set(r["backends"]))
    data = {"scope": args.scope,
            "snapshots": [s["id"] for s in snaps],
            "defects": own,
            "third_party": foreign if args.third_party else [],
            "third_party_count": len(foreign)}

    def block(title, items):
        print(f"{title}: {len(items)}")
        if not items:
            return
        rows = []
        for r in items:
            rows.append([r["cid"], r["impact"], r["checker"], r["component"],
                         ",".join(r["backends"]) or "-",
                         r["first_version"], r["last_version"],
                         "/".join(x or "-" for x in (r["classification"],
                                                     r["action"],
                                                     r["owner"]))])
            rows.append(["", f"{r['file']}: {r['function']}", r["type"],
                         "", "", "", "", ""])
        table(rows, ["cid", "impact", "checker", "component", "backends",
                     "first", "last", "class/action/owner"])

    def text():
        if snaps:
            print("snapshots: " + ", ".join(
                f"{s['id']} ({s['backend'] or '?'})" for s in snaps))
        block("defects", own)
        if args.third_party:
            block("third-party defects", foreign)
        elif foreign:
            print(f"third-party defects: {len(foreign)} (--third-party lists them)")
    emit(args, data, text)


def events_print(events, depth):
    for ev in sorted(events, key=lambda e: int(get(e, "eventNumber",
                                                    default=0))):
        main = get(ev, "main") == "true"
        path = get(ev, "fileId", "filePathname", default="?")
        line = get(ev, "lineNumber", default="?")
        tag = get(ev, "eventTag", default="")
        desc = get(ev, "eventDescription", default="")
        mark = "*" if main else " "
        print(f"  {mark}{'  ' * depth}{get(ev, 'eventNumber', default='')}"
              f"  {path}:{line}  [{tag}]  {desc}")
        events_print(many(ev, "events"), depth + 1)


def cmd_show(args):
    conn = connect_open()
    info = project_info(conn, project_get(args))
    defects = conn.call("defectservice", "getStreamDefects",
                        mergedDefectIdDataObjs=[{"cid": c} for c in args.cid],
                        filterSpec={"includeDefectInstances": True,
                                    "includeHistory": False,
                                    "includeTotalDefectInstanceCount": False,
                                    "maxDefectInstances": 20,
                                    "streamIdList": [{"name":
                                                      info["stream"]}]})

    def text():
        for d in defects:
            print(f"CID {get(d, 'cid')}  {get(d, 'checkerName', default='')}"
                  f"  stream {get(d, 'streamId', 'name', default='')}")
            for inst in many(d, "defectInstances"):
                fn = get(inst, "function", "functionDisplayName", default="")
                path = get(inst, "function", "fileId", "filePathname",
                           default="")
                print(f" instance: {get(inst, 'type', 'displayName', default='')}"
                      f" ({get(inst, 'impact', 'displayName', default='')})"
                      f" in {fn}, {path}")
                if get(inst, "longDescription"):
                    print(f"  {get(inst, 'longDescription')}")
                if get(inst, "localEffect"):
                    print(f"  local effect: {get(inst, 'localEffect')}")
                events_print(many(inst, "events"), 0)
            print()
    emit(args, defects, text)


def cmd_triage(args):
    needs_comment = args.classification in ("False Positive", "Intentional")
    if needs_comment and not args.comment:
        die(f"--comment is required for {args.classification}: the reasoning"
            " goes on record in Coverity")
    conn = connect_open()
    info = project_info(conn, project_get(args))
    store = args.store or info["triage_store"]
    if not store:
        die("no triage store found for the stream; pass --store")
    values = [("Classification", args.classification)]
    if args.action:
        values.append(("Action", args.action))
    if args.owner:
        values.append(("Owner", args.owner))
    if args.comment:
        values.append(("Comment", args.comment))
    conn.call("defectservice", "updateTriageForCIDsInTriageStore",
              triageStore={"name": store},
              mergedDefectIdDataObjs=[{"cid": c} for c in args.cid],
              defectState={"defectStateAttributeValues": [
                  {"attributeDefinitionId": {"name": k},
                   "attributeValueId": {"name": v}} for k, v in values]})
    data = {"cids": args.cid, "store": store, "attributes": dict(values)}
    emit(args, data, lambda: print(
        f"triaged {', '.join(str(c) for c in args.cid)} in {store}: "
        + ", ".join(f"{k}={v}" for k, v in values)))


def cmd_history(args):
    conn = connect_open()
    info = project_info(conn, project_get(args))
    triage = conn.call("defectservice", "getTriageHistory",
                       mergedDefectIdDataObj={"cid": args.cid},
                       triageStoreIds=[{"name": info["triage_store"]}])
    changes = conn.call("defectservice", "getMergedDefectHistory",
                        mergedDefectIdDataObj={"cid": args.cid},
                        streamIds=[{"name": info["stream"]}])
    data = {"cid": args.cid, "triage": triage, "changes": changes}

    def text():
        print(f"CID {args.cid} triage history:")
        for t in triage:
            attrs = {get(a, "attributeDefinitionId", "name"):
                     get(a, "attributeValueId", "name", default="")
                     for a in many(t, "attributes")}
            print(f"  #{get(t, 'id', default='')}: "
                  + ", ".join(f"{k}={v}" for k, v in attrs.items()))
        print(f"CID {args.cid} change history:")
        for c in changes:
            print(f"  {get(c, 'dateModified', default='')[:19]}"
                  f"  {get(c, 'userModified', default='')}"
                  f"  {get(c, 'comments', default='')}")
            for ch in many(c, "attributeChanges"):
                print(f"    {get(ch, 'fieldName', default='')}: "
                      f"{get(ch, 'oldValue', default='')} -> "
                      f"{get(ch, 'newValue', default='')}")
    emit(args, data, text)


def cmd_fixed(args):
    conn = connect_open()
    rules = rules_load()
    info = project_info(conn, project_get(args))
    snaps = snapshots_all(conn, info["stream"])
    by_id = {s["id"]: s for s in snaps}
    newest = snapshots_current(snaps)
    claims = git_claims()
    fixed, outstanding = [], []
    for d in defects_project(conn, info["project"]):
        row = row_from(d, rules)
        last = by_id.get(row["last_snapshot"])
        backend = last["backend"] if last else None
        current = newest.get(backend)
        row["backend"] = backend
        row["fixed"] = bool(current) and current["id"] != row["last_snapshot"]
        row["commits"] = claims.get(row["cid"], [])
        (fixed if row["fixed"] else outstanding).append(row)
    claimed_open = [r for r in outstanding if r["commits"]]
    data = {"fixed": fixed, "claimed_but_outstanding": claimed_open}

    def text():
        print(f"fixed: {len(fixed)}")
        for r in fixed:
            who = ", ".join(f"{sha} ({subj})" for sha, subj in r["commits"]) \
                or "no commit claims it"
            print(f"  CID {r['cid']}  {r['checker']}  {r['file']}  "
                  f"last seen {r['last_version']} ({r['backend'] or '?'})"
                  f"  {who}")
        print(f"claimed by a commit but still outstanding: {len(claimed_open)}")
        for r in claimed_open:
            for sha, subj in r["commits"]:
                print(f"  CID {r['cid']}  {r['checker']}  {r['file']}  "
                      f"claimed by {sha} ({subj})")
    emit(args, data, text)


def cmd_components(args):
    rules = rules_load()
    local = [{"pattern": p, "component": c} for _, p, c in rules]
    remote = None
    note = ""
    try:
        conn = connect_open()
        info = project_info(conn, project_get(args))
        maps = conn.call("configurationservice", "getComponentMaps",
                         filterSpec={})
        for m in maps:
            if get(m, "componentMapId", "name") != info["component_map"]:
                continue
            remote = [{"pattern": get(r, "pathPattern", default=""),
                       "component": get(r, "componentId", "name", default="")}
                      for r in many(m, "componentPathRules")]
    except Fail as e:
        note = str(e)
    data = {"local": local, "remote": remote, "note": note}

    def text():
        print("rules for the Analysis Settings tab, in order:")
        table([[r["component"], r["pattern"]] for r in local],
              ["component", "path pattern"])
        if remote is None:
            print(f"Scan's map not compared: {note}")
            return
        if remote == local:
            print("Scan's component map matches.")
            return
        print("Scan's component map differs:")
        table([[r["component"], r["pattern"]] for r in remote],
              ["component", "path pattern"])
    emit(args, data, text)


class TextOnly(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.hidden += 1
        if tag == "br":
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.hidden -= 1
        if tag in ("p", "div", "pre", "tr", "li"):
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def html_text(text):
    p = TextOnly()
    p.feed(text)
    return "".join(p.parts)


def mail_url():
    url = os.environ.get("COVERITY_IMAP_URL",
                         "imaps://coverity@pidgin.makrotopia.org/")
    u = urllib.parse.urlsplit(url)
    if u.scheme != "imaps" or not u.hostname:
        die(f"COVERITY_IMAP_URL must be imaps://[user@]host[:port]/[folder], not {url}")
    folder = urllib.parse.unquote(u.path.lstrip("/")) or "INBOX"
    return u.hostname, u.port or 993, u.username, folder


def mail_credentials(host, user):
    password = os.environ.get("COVERITY_IMAP_PASSWORD")
    if user and password:
        return user, password
    try:
        entry = netrc.netrc().authenticators(host)
    except FileNotFoundError:
        entry = None
    except netrc.NetrcParseError as e:
        die(f"~/.netrc: {e}")
    if entry is None:
        die(f"no password for {host}: set COVERITY_IMAP_PASSWORD or a"
            " ~/.netrc entry for the host")
    login, _, netrc_password = entry
    return user or login, password or netrc_password


def mail_open(readonly):
    host, port, user, folder = mail_url()
    user, password = mail_credentials(host, user)
    conn = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
    try:
        conn.login(user, password)
    except imaplib.IMAP4.error as e:
        die(f"login to {host} as {user} refused: {e}")
    typ, data = conn.select(folder, readonly=readonly)
    if typ != "OK":
        die(f"cannot select folder {folder}: {data}")
    return conn


def mail_uids(conn, criteria):
    typ, data = conn.uid("SEARCH", None, *criteria)
    if typ != "OK":
        die(f"IMAP search failed: {data}")
    return [u.decode() for u in data[0].split()]


def mail_fetch(conn, uid):
    typ, data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
    if typ != "OK" or not data or not isinstance(data[0], tuple):
        die(f"IMAP fetch of UID {uid} failed: {data}")
    return data[0][1]


def mail_text(msg):
    body = msg.get_body(preferencelist=("plain", "html"))
    if body is None:
        return ""
    text = body.get_content()
    if body.get_content_type() == "text/html":
        text = html_text(text)
    return text.replace("\r\n", "\n")


RE_SUBJECT_NEW = re.compile(r"^New Defects reported by Coverity Scan for (.+)$")
RE_NEW = re.compile(r"^(\d+) new defect\(s\) introduced to (.+?) found with"
                    r" Coverity Scan\.?$")
RE_FIXED = re.compile(r"^(\d+) defect\(s\), reported by Coverity Scan earlier,"
                      r" were marked fixed")
RE_SHOWING = re.compile(r"^Showing (\d+) of (\d+) defect\(s\)")
RE_SUMMARY = re.compile(r"^\*\* CID (\d+):")
RE_DETAIL = re.compile(r"^\*\*\* CID (\d+):\s*(.*?)\s*\((\w+)\)\s*$")
RE_LOCATION = re.compile(r"^/(\S+): (\d+) in (.+)\(\)$")
RE_END = re.compile(r"^(To view the defects in Coverity Scan|_{20,})")


def location_join(lines, i):
    """The location line at i, rejoined when an archive soft-wrapped it."""
    text = lines[i].rstrip()
    j = i + 1
    while not RE_LOCATION.match(text) and text.startswith("/") \
            and j < len(lines) and j - i < 5:
        text = text + " " + lines[j].strip()
        j += 1
    m = RE_LOCATION.match(text)
    if not m:
        return None, i + 1
    return {"file": m.group(1), "line": int(m.group(2)),
            "function": m.group(3)}, j


def block_parse(lines, i, end):
    """One '*** CID' detail block: the defect and its located occurrences."""
    m = RE_DETAIL.match(lines[i])
    defect = {"cid": int(m.group(1)), "kind": m.group(2),
              "checker": m.group(3), "occurrences": []}
    i += 1
    current = None
    while i < end:
        line = lines[i]
        if line.startswith("/"):
            loc, i = location_join(lines, i)
            if loc:
                current = dict(loc, excerpt=[], event=[])
                defect["occurrences"].append(current)
                continue
        if current is not None:
            current["excerpt"].append(line.rstrip())
            if line.startswith(">>>") and "CID " not in line[:14]:
                current["event"].append(line[3:].strip())
        i += 1
    for occ in defect["occurrences"]:
        occ["excerpt"] = "\n".join(occ["excerpt"]).strip("\n")
        occ["event"] = " ".join(occ["event"])
    return defect


def digest_parse(text):
    lines = text.split("\n")
    event = {"type": "new-defects", "project": None, "new": None,
             "fixed": 0, "shown": None, "defects": []}
    starts = []
    enders = []
    for i, line in enumerate(lines):
        s = line.strip()
        if m := RE_NEW.match(s):
            event["new"], event["project"] = int(m.group(1)), m.group(2)
        elif m := RE_FIXED.match(s):
            event["fixed"] = int(m.group(1))
        elif m := RE_SHOWING.match(s):
            event["shown"] = int(m.group(1))
        elif RE_DETAIL.match(s):
            starts.append(i)
        elif RE_END.match(s):
            enders.append(i)
    end = len(lines)
    if starts:
        end = next((e for e in enders if e > starts[-1]), end)
    for n, start in enumerate(starts):
        stop = starts[n + 1] if n + 1 < len(starts) else end
        stop = next((k for k in range(start + 1, stop)
                     if RE_SUMMARY.match(lines[k].strip())), stop)
        event["defects"].append(block_parse(lines, start, stop))
    for d in event["defects"]:
        first = d["occurrences"][0] if d["occurrences"] else {}
        for key in ("file", "line", "function", "excerpt", "event"):
            d[key] = first.get(key)
        d["more"] = d["occurrences"][1:]
        del d["occurrences"]
    if event["new"] is None and not event["defects"]:
        return None
    event["partial"] = bool(event["shown"] is not None
                            and event["new"] is not None
                            and event["shown"] < event["new"])
    return event


def mail_event(uid, msg):
    subject = (msg["subject"] or "").replace("\n", " ").strip()
    base = {"uid": uid, "date": msg["date"], "subject": subject}
    if RE_SUBJECT_NEW.match(subject):
        parsed = digest_parse(mail_text(msg))
        if parsed:
            return dict(base, **parsed)
    return dict(base, type="unknown")


def mail_poll(conn):
    events = []
    for uid in mail_uids(conn, ["UNSEEN", "FROM", f'"{SCAN_SENDER}"']):
        msg = email.message_from_bytes(mail_fetch(conn, uid),
                                       policy=email.policy.default)
        events.append(mail_event(uid, msg))
    return events


def events_text(events):
    if not events:
        print("no unhandled Scan mail")
    for ev in events:
        print(f"UID {ev['uid']}  {ev['date']}  {ev['subject']}")
        if ev["type"] != "new-defects":
            print("  not parsed; mail show UID --raw prints it")
            continue
        print(f"  {ev['new']} new, {ev['fixed']} marked fixed, "
              f"{ev['shown']} shown"
              + (", the rest is in list" if ev["partial"] else ""))
        for d in ev["defects"]:
            print(f"  CID {d['cid']}  {d['checker']}  {d['kind']}")
            if d["file"]:
                print(f"    {d['file']}:{d['line']} in {d['function']}()")
            if d["event"]:
                print(f"    {d['event']}")
            for occ in d["more"]:
                print(f"    also {occ['file']}:{occ['line']} in {occ['function']}()")


def cmd_mail_poll(args):
    conn = mail_open(readonly=True)
    events = mail_poll(conn)
    conn.logout()
    emit(args, events, lambda: events_text(events))


def cmd_mail_wait(args):
    conn = mail_open(readonly=True)
    if not hasattr(conn, "idle"):
        die("mail wait needs Python 3.13 or newer for IMAP IDLE; use mail poll")
    deadline = None if args.timeout is None else time.monotonic() + args.timeout
    events = mail_poll(conn)
    while not events:
        span = IDLE_SPAN
        if deadline is not None:
            span = min(span, deadline - time.monotonic())
            if span <= 0:
                break
        with conn.idle(duration=span) as idler:
            for typ, _ in idler:
                if typ == "EXISTS":
                    break
        events = mail_poll(conn)
    conn.logout()
    emit(args, events, lambda: events_text(events))
    return 0 if events else 3


def cmd_mail_show(args):
    conn = mail_open(readonly=True)
    raw = mail_fetch(conn, args.uid)
    conn.logout()
    if args.raw:
        sys.stdout.buffer.write(raw)
        return 0
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    ev = mail_event(args.uid, msg)
    emit(args, ev, lambda: events_text([ev]))
    return 0


def cmd_mail_done(args):
    conn = mail_open(readonly=False)
    for uid in args.uid:
        typ, data = conn.uid("STORE", uid, "+FLAGS", r"(\Seen)")
        if typ != "OK":
            die(f"marking UID {uid} failed: {data}")
    conn.logout()
    emit(args, {"done": args.uid},
         lambda: print("handled: " + ", ".join(args.uid)))


def parser_build():
    p = argparse.ArgumentParser(
        description="Read and triage comrade's Coverity Scan results.")
    p.add_argument("--json", action="store_true", help="machine output")
    p.add_argument("--project", help="Scan project name (owner/repo)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("streams").set_defaults(func=cmd_streams)
    sub.add_parser("snapshots").set_defaults(func=cmd_snapshots)

    s = sub.add_parser("list")
    s.add_argument("--scope", choices=("current", "last", "all"),
                   default="current")
    s.add_argument("--third-party", action="store_true",
                   help="list the third-party rows too")
    s.add_argument("--all-triage", action="store_true",
                   help="include false positives, intentional and ignored")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("show")
    s.add_argument("cid", type=int, nargs="+")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("triage")
    s.add_argument("cid", type=int, nargs="+")
    s.add_argument("--classification", required=True,
                   choices=("Unclassified", "Pending", "False Positive",
                            "Intentional", "Bug"))
    s.add_argument("--action", choices=("Undecided", "Fix Required",
                                        "Fix Submitted", "Modeling Required",
                                        "Ignore"))
    s.add_argument("--owner")
    s.add_argument("--comment")
    s.add_argument("--store", help="triage store (default: the stream's)")
    s.set_defaults(func=cmd_triage)

    s = sub.add_parser("history")
    s.add_argument("cid", type=int)
    s.set_defaults(func=cmd_history)

    sub.add_parser("fixed").set_defaults(func=cmd_fixed)
    sub.add_parser("components").set_defaults(func=cmd_components)

    m = sub.add_parser("mail").add_subparsers(dest="mailcmd", required=True)
    m.add_parser("poll").set_defaults(func=cmd_mail_poll)
    s = m.add_parser("wait")
    s.add_argument("--timeout", type=float, help="seconds to wait at most")
    s.set_defaults(func=cmd_mail_wait)
    s = m.add_parser("show")
    s.add_argument("uid")
    s.add_argument("--raw", action="store_true", help="the mail as received")
    s.set_defaults(func=cmd_mail_show)
    s = m.add_parser("done")
    s.add_argument("uid", nargs="+")
    s.set_defaults(func=cmd_mail_done)
    return p


def main():
    args = parser_build().parse_args()
    try:
        rc = args.func(args)
    except Fail as e:
        print(f"covscan: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return rc or 0


if __name__ == "__main__":
    sys.exit(main())
