var words = @["alpha", "beta", "gamma"]
words.add("delta")
var joined = ""
for i, w in words:
  joined.add($i & ":" & w & " ")
echo joined

var buf: seq[int] = @[]
for i in 0 ..< 10:
  buf.add(i * i)
echo buf
