import std/[strutils, tables, sequtils, algorithm]

let text = "the quick brown fox jumps over the lazy dog the fox is quick"
var counts = initCountTable[string]()
for w in text.split(' '):
  counts.inc(w.toLowerAscii)

var ranked = toSeq(counts.pairs)
ranked.sort(proc(a, b: (string, int)): int = b[1] - a[1])

for (word, n) in ranked[0 ..< min(3, ranked.len)]:
  echo word, "=", n

let nums = @[5, 2, 8, 1, 9, 3]
echo nums.sorted()
echo nums.mapIt(it * 2).foldl(a + b)
