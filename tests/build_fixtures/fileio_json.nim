import std/[json, os]

let j = %*{
  "name": "nim-fixture",
  "version": 1,
  "tags": ["alpha", "beta", "gamma"],
  "nested": {"a": 1, "b": true}
}

let path = getTempDir() / "nim_fixture.json"
writeFile(path, $j)
let parsed = parseFile(path)
echo parsed["name"].getStr
echo parsed["tags"].len
removeFile(path)
