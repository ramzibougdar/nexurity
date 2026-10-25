#!/usr/bin/env python3
"""CVSS 4.0 vector validation and base score computation.

Port of the FIRST CVSS v4.0 calculator (cvss_score.js, cvss_lookup.js,
max_composed.js, max_severity.js, metrics.js):
https://github.com/FIRSTdotorg/cvss-v4-calculator

Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors.
SPDX-License-Identifier: BSD-2-Clause (see NOTICE.md for the full licence text).

Python standard library only. Usage:
    cvss4.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    cvss4.py --json "<vector>"
"""
import argparse
import json
import math
import sys

PREFIX = "CVSS:4.0"

# Metric order and allowed values (metrics.js). The 11 base metrics are mandatory.
METRICS = {
    "AV": ["N", "A", "L", "P"], "AC": ["L", "H"], "AT": ["N", "P"],
    "PR": ["N", "L", "H"], "UI": ["N", "P", "A"],
    "VC": ["H", "L", "N"], "VI": ["H", "L", "N"], "VA": ["H", "L", "N"],
    "SC": ["H", "L", "N"], "SI": ["H", "L", "N"], "SA": ["H", "L", "N"],
    "E": ["X", "A", "P", "U"],
    "CR": ["X", "H", "M", "L"], "IR": ["X", "H", "M", "L"], "AR": ["X", "H", "M", "L"],
    "MAV": ["X", "N", "A", "L", "P"], "MAC": ["X", "L", "H"], "MAT": ["X", "N", "P"],
    "MPR": ["X", "N", "L", "H"], "MUI": ["X", "N", "P", "A"],
    "MVC": ["X", "H", "L", "N"], "MVI": ["X", "H", "L", "N"], "MVA": ["X", "H", "L", "N"],
    "MSC": ["X", "H", "L", "N"], "MSI": ["X", "S", "H", "L", "N"], "MSA": ["X", "S", "H", "L", "N"],
    "S": ["X", "N", "P"], "AU": ["X", "N", "Y"], "R": ["X", "A", "U", "I"],
    "V": ["X", "D", "C"], "RE": ["X", "L", "M", "H"],
    "U": ["X", "Clear", "Green", "Amber", "Red"],
}
BASE_COUNT = 11

# Score of the highest-severity vector of each MacroVector (cvss_lookup.js).
LOOKUP = {
    "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2,
    "000100": 10, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8, "000220": 8.1, "000221": 6.8,
    "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
    "001200": 8.8, "001201": 8, "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9, "002111": 6.9, "002121": 5,
    "002201": 6.9, "002211": 5.5, "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9,
    "010111": 8.3, "010120": 8.4, "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5, "011001": 9.3, "011010": 9.2,
    "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8,
    "011111": 7.2, "011120": 7, "011121": 5.9, "011200": 8.4, "011201": 7, "011210": 7.1,
    "011211": 5.2, "011220": 5, "011221": 3, "012001": 8.6, "012011": 7.5, "012021": 5.2,
    "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3, "012211": 2.9, "012221": 1.7,
    "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4,
    "100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
    "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
    "102001": 8.3, "102011": 7, "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5, "110001": 9, "110010": 8.8,
    "110011": 7.6, "110020": 7.6, "110021": 7, "110100": 9, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8,
    "110211": 5.9, "110220": 5.2, "110221": 3, "111000": 8.9, "111001": 7.8, "111010": 7.6,
    "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4, "111101": 5.9, "111110": 5.7,
    "111111": 5.7, "111120": 4.7, "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3,
    "112101": 5.8, "112111": 2.6, "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
    "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4, "200220": 4, "200221": 2.2,
    "201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
    "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2, "202101": 4.7, "202111": 2.1, "202121": 1.1,
    "202201": 2.4, "202211": 0.9, "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
    "210011": 5.3, "210020": 6, "210021": 5, "210100": 7.3, "210101": 5.5, "210110": 5.9,
    "210111": 4, "210120": 4.1, "210121": 2, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2, "210221": 1.1, "211000": 7.5, "211001": 5.5, "211010": 5.8,
    "211011": 4.5, "211020": 4, "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
    "211111": 1.8, "211120": 2, "211121": 0.9, "211200": 4.6, "211201": 1.8, "211210": 1.7,
    "211211": 0.7, "211220": 0.8, "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1, "212211": 0.3, "212221": 0.1,
}

# Highest-severity vectors per EQ level (max_composed.js).
MAX_COMPOSED = {
    "eq1": {0: ["AV:N/PR:N/UI:N/"],
            1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
            2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]},
    "eq2": {0: ["AC:L/AT:N/"], 1: ["AC:H/AT:N/", "AC:L/AT:P/"]},
    "eq3": {
        0: {"0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]},
        1: {"0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            "1": ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                  "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                  "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"]},
        2: {"1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
    },
    "eq4": {0: ["SC:H/SI:S/SA:S/"], 1: ["SC:H/SI:H/SA:H/"], 2: ["SC:L/SI:L/SA:L/"]},
    "eq5": {0: ["E:A/"], 1: ["E:P/"], 2: ["E:U/"]},
}

# Maximal severity distances per EQ level, +1 (max_severity.js).
MAX_SEVERITY = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}
DISTANCE_ORDER = ["AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"]


class InvalidVector(ValueError):
    pass


def parse(vector):
    """Return {metric: value} for every metric (X when absent). Raise InvalidVector."""
    if not isinstance(vector, str) or not vector.strip():
        raise InvalidVector("empty vector")
    parts = vector.strip().split("/")
    if parts[0] != PREFIX:
        raise InvalidVector("missing CVSS:4.0 prefix")
    order = list(METRICS.items())
    selected = {name: "X" for name in METRICS}
    oi = 0
    for part in parts[1:]:
        if part.count(":") != 1:
            raise InvalidVector("malformed metric %r" % part)
        key, value = part.split(":")
        while True:
            if oi >= len(order):
                raise InvalidVector("unknown, duplicate or out-of-order metric %r" % key)
            name, allowed = order[oi]
            oi += 1
            if key != name:
                if oi <= BASE_COUNT:
                    raise InvalidVector("missing mandatory base metric %s" % name)
                continue
            break
        if value not in allowed:
            raise InvalidVector("value %r not allowed for %s (expected one of %s)" % (value, key, ", ".join(allowed)))
        selected[key] = value
    if oi < BASE_COUNT:
        raise InvalidVector("missing mandatory base metrics")
    return selected


def _m(sel, metric):
    value = sel[metric]
    if metric == "E" and value == "X":
        return "A"
    if metric in ("CR", "IR", "AR") and value == "X":
        return "H"
    modified = sel.get("M" + metric)
    if modified is not None and modified != "X":
        return modified
    return value


def macro_vector(sel):
    m = lambda k: _m(sel, k)
    if m("AV") == "N" and m("PR") == "N" and m("UI") == "N":
        eq1 = 0
    elif (m("AV") == "N" or m("PR") == "N" or m("UI") == "N") and m("AV") != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if (m("AC") == "L" and m("AT") == "N") else 1
    if m("VC") == "H" and m("VI") == "H":
        eq3 = 0
    elif m("VC") == "H" or m("VI") == "H" or m("VA") == "H":
        eq3 = 1
    else:
        eq3 = 2
    if m("MSI") == "S" or m("MSA") == "S":
        eq4 = 0
    elif m("SC") == "H" or m("SI") == "H" or m("SA") == "H":
        eq4 = 1
    else:
        eq4 = 2
    eq5 = {"A": 0, "P": 1, "U": 2}[m("E")]
    if (m("CR") == "H" and m("VC") == "H") or (m("IR") == "H" and m("VI") == "H") or (m("AR") == "H" and m("VA") == "H"):
        eq6 = 0
    else:
        eq6 = 1
    return "%d%d%d%d%d%d" % (eq1, eq2, eq3, eq4, eq5, eq6)


def _extract(metric, vector_part):
    start = vector_part.index(metric + ":") + len(metric) + 1
    end = vector_part.find("/", start)
    return vector_part[start:end] if end > 0 else vector_part[start:]


def _js_round_1(value):
    # Math.round(value * 10) / 10, as in the reference calculator
    return math.floor(value * 10 + 0.5) / 10


def score(vector):
    """Base (or threat/environmental, if given) score of a CVSS 4.0 vector."""
    sel = parse(vector)
    if all(_m(sel, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    macro = macro_vector(sel)
    value = LOOKUP[macro]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in macro)

    def key(*digits):
        return "".join(str(d) for d in digits)

    nan = float("nan")
    look = lambda k: LOOKUP.get(k, nan)
    score_eq1_next = look(key(eq1 + 1, eq2, eq3, eq4, eq5, eq6))
    score_eq2_next = look(key(eq1, eq2 + 1, eq3, eq4, eq5, eq6))
    if eq3 == 0 and eq6 == 0:
        left = look(key(eq1, eq2, eq3, eq4, eq5, eq6 + 1))
        right = look(key(eq1, eq2, eq3 + 1, eq4, eq5, eq6))
        score_eq3eq6_next = left if left > right else right
    elif eq3 == 1 and eq6 == 1:
        score_eq3eq6_next = look(key(eq1, eq2, eq3 + 1, eq4, eq5, eq6))
    elif eq3 == 0 and eq6 == 1:
        score_eq3eq6_next = look(key(eq1, eq2, eq3 + 1, eq4, eq5, eq6))
    elif eq3 == 1 and eq6 == 0:
        score_eq3eq6_next = look(key(eq1, eq2, eq3, eq4, eq5, eq6 + 1))
    else:
        score_eq3eq6_next = look(key(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1))
    score_eq4_next = look(key(eq1, eq2, eq3, eq4 + 1, eq5, eq6))
    score_eq5_next = look(key(eq1, eq2, eq3, eq4, eq5 + 1, eq6))

    max_vectors = [
        a + b + c + d + e
        for a in MAX_COMPOSED["eq1"][eq1]
        for b in MAX_COMPOSED["eq2"][eq2]
        for c in MAX_COMPOSED["eq3"][eq3][str(eq6)]
        for d in MAX_COMPOSED["eq4"][eq4]
        for e in MAX_COMPOSED["eq5"][eq5]
    ]
    dist = {}
    for max_vector in max_vectors:
        dist = {k: LEVELS[k][_m(sel, k)] - LEVELS[k][_extract(k, max_vector)] for k in DISTANCE_ORDER}
        if any(v < 0 for v in dist.values()):
            continue
        break

    cur_eq1 = dist["AV"] + dist["PR"] + dist["UI"]
    cur_eq2 = dist["AC"] + dist["AT"]
    cur_eq3eq6 = dist["VC"] + dist["VI"] + dist["VA"] + dist["CR"] + dist["IR"] + dist["AR"]
    cur_eq4 = dist["SC"] + dist["SI"] + dist["SA"]

    step = 0.1
    max_eq1 = MAX_SEVERITY["eq1"][eq1] * step
    max_eq2 = MAX_SEVERITY["eq2"][eq2] * step
    max_eq3eq6 = MAX_SEVERITY["eq3eq6"][eq3][eq6] * step
    max_eq4 = MAX_SEVERITY["eq4"][eq4] * step

    n_lower = 0
    total = 0.0
    for available, current, maximum in (
        (value - score_eq1_next, cur_eq1, max_eq1),
        (value - score_eq2_next, cur_eq2, max_eq2),
        (value - score_eq3eq6_next, cur_eq3eq6, max_eq3eq6),
        (value - score_eq4_next, cur_eq4, max_eq4),
    ):
        if not math.isnan(available):
            n_lower += 1
            total += available * (current / maximum)
    if not math.isnan(value - score_eq5_next):
        n_lower += 1  # the EQ5 proportion is always 0

    mean = total / n_lower if n_lower else 0.0
    value -= mean
    value = min(max(value, 0.0), 10.0)
    return _js_round_1(value)


def severity(value):
    if value == 0:
        return "none"
    if value < 4.0:
        return "low"
    if value < 7.0:
        return "medium"
    if value < 9.0:
        return "high"
    return "critical"


def main(argv=None):
    parser = argparse.ArgumentParser(description="CVSS 4.0 vector -> score and severity")
    parser.add_argument("vector")
    parser.add_argument("--json", action="store_true", help="print a JSON object")
    args = parser.parse_args(argv)
    try:
        value = score(args.vector)
    except InvalidVector as exc:
        if args.json:
            print(json.dumps({"vector": args.vector, "valid": False, "error": str(exc)}))
        else:
            print("invalid vector: %s" % exc, file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"vector": args.vector, "valid": True, "score": value, "severity": severity(value)}))
    else:
        print("%.1f %s" % (value, severity(value)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
