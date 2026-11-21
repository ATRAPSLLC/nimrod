type
  MyError = object of CatchableError
  OtherError = object of ValueError

proc inner(x: int) =
  if x < 0:
    raise newException(MyError, "negative input")
  if x == 0:
    raise newException(OtherError, "zero input")

proc outer(x: int): string =
  try:
    inner(x)
    result = "ok"
  except MyError as e:
    result = "my: " & e.msg
  except OtherError as e:
    result = "other: " & e.msg

echo outer(-1)
echo outer(0)
echo outer(1)
