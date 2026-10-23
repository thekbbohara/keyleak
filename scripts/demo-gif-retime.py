"""Retime a recording of `keyleak demo` for the README GIF.

The scan prints its whole report in one burst. This keeps the typed command,
shows the first screen (headline, critical keys, the OpenAI key) and holds it,
then scrolls the rest in steps of a few lines. The text is untouched.

usage: demo-gif-retime.py RAW.cast OUT.cast ROWS
"""
import json
import re
import sys

src, dst, height = sys.argv[1], sys.argv[2], int(sys.argv[3])
lines = open(src).read().splitlines()
head = json.loads(lines[0])
head["height"] = height
head.pop("timestamp", None)
events = [json.loads(line) for line in lines[1:]]

# Prompt and typed command, up to the Enter.
enter = next(i for i, e in enumerate(events) if "\n" in e[2])
typing = events[:enter]
t = typing[-1][0] + 0.6
output, _, _ = "".join(e[2] for e in events[enter:]).rpartition("$ ")
out = output.split("\r\n")

ansi = re.compile(r"\x1b\[[0-9;]*m")


def rows(s):
    return max(1, -(-len(ansi.sub("", s)) // head["width"]))


# First screen: everything before the second HIGH key. It must fit with the
# command line above it.
first = [i for i, line in enumerate(out) if "HIGH" in line][1]
if 1 + sum(rows(line) for line in out[:first]) > height:
    sys.exit(f"first screen does not fit in {height} rows")

res = typing + [[t, "o", "\r\n".join(out[:first]) + "\r\n"]]
t += 3.6
for i in range(first, len(out), 6):
    res.append([round(t, 3), "o", "\r\n".join(out[i : i + 6]) + "\r\n"])
    t += 0.2
res.append([round(t, 3), "o", "$ "])

with open(dst, "w") as f:
    f.write(json.dumps(head) + "\n")
    for e in res:
        f.write(json.dumps(e) + "\n")
