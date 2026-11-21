import std/asyncdispatch

type
  Shape = ref object of RootObj
    name: string
  Circle = ref object of Shape
    r: float
  Square = ref object of Shape
    side: float

method area(s: Shape): float {.base.} = 0.0
method area(c: Circle): float = 3.0 * c.r * c.r
method area(s: Square): float = s.side * s.side

proc makeCounter(start: int): proc (): int =
  var n = start
  result = proc (): int =
    inc n
    n

proc twice[T](x: T): T = x + x

type Resource = ref object
  id: int

proc release(r: Resource) = echo "release ", r.id

proc fetch(x: int): Future[int] {.async.} =
  await sleepAsync(1)
  return x * 2

proc pipeline(): Future[int] {.async.} =
  let a = await fetch(1)
  let b = await fetch(2)
  return a + b

proc main() =
  let shapes: seq[Shape] = @[Shape(name: "s"), Circle(name: "c", r: 2.0),
                             Square(name: "q", side: 3.0)]
  for s in shapes:
    echo s.name, " ", s.area
  let next = makeCounter(10)
  echo next(), " ", next()
  echo twice(21), " ", twice(1.5)
  var r: Resource
  new(r, release)
  r.id = 7
  echo waitFor pipeline()

main()
