# Nim 2.4 sum types (object `case` without a discriminator) next to a
# classic object variant, so RTTI for both shapes can be compared.
type
  Node = ref object
    case
    of AddOpr, SubOpr:
      a, b: Node
    of Value:
      val: int

  Kind = enum kInt, kStr
  Variant = ref object
    case kind: Kind
    of kInt: i: int
    of kStr: s: string

proc eval(n: Node): int =
  case n
  of Value(v): v
  of AddOpr(a, b): eval(a) + eval(b)
  of SubOpr(a, b): eval(a) - eval(b)

let tree = AddOpr(a: Value(val: 40), b: SubOpr(a: Value(val: 5), b: Value(val: 3)))
echo eval(tree)
let v = Variant(kind: kStr, s: "variant payload")
echo v.s
echo $tree[]
