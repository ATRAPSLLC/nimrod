# gdb -batch -x dump.py --args <binary>   (env OUT=<dir>)
#
# Runs the fixture to its exit_group syscall (memory intact; RTTI objects are
# not modified after the DatInit000 functions filled them) and dumps every
# writable mapping that belongs to the image, including the anonymous
# mapping that continues .bss, as <OUT>/<start>-<end>.bin, plus
# <OUT>/base.txt with the image's load base.
import gdb, os

out = os.environ["OUT"]
gdb.execute("set pagination off")
gdb.execute("catch syscall exit_group", to_string=True)
gdb.execute("run >/dev/null 2>&1 </dev/null", to_string=True)
path = os.path.realpath(gdb.current_progspace().filename)
base = None
last_end = None
for line in gdb.execute("info proc mappings", to_string=True).splitlines():
    parts = line.split()
    if len(parts) < 5 or not parts[0].startswith("0x"):
        continue
    start, end = int(parts[0], 16), int(parts[1], 16)
    objfile = parts[-1] if len(parts) >= 6 else ""
    perms = parts[4] if len(parts) >= 6 else (parts[4] if len(parts) == 5 else "")
    mine = objfile and os.path.realpath(objfile) == path
    if mine:
        if base is None:
            base = start
        if "w" in perms:
            gdb.execute(f"dump binary memory {out}/{start:x}-{end:x}.bin {start} {end}")
        last_end = end
    elif base is not None and last_end == start and "w" in perms and not objfile:
        gdb.execute(f"dump binary memory {out}/{start:x}-{end:x}.bin {start} {end}")
        last_end = end
with open(f"{out}/base.txt", "w") as f:
    f.write(f"{base:x}\n")
gdb.execute("kill")
