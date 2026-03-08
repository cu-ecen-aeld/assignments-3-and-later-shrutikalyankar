# Assignment 7 – Faulty Driver Oops Analysis

## Command Used

```sh
echo "hello_world" > /dev/faulty
````

---

## Kernel Error Observed

From `dmesg`:

* `Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000`
* `pc : faulty_write+0x8/0x10 [faulty]`
* `Modules linked in: hello(O) faulty(O) scull(O)`

---

## Root Cause

The crash occurs inside the `faulty_write()` function of the `faulty` kernel module.

The program counter shows:

```
faulty_write+0x8/0x10
```

The register dump shows:

```
x1 : 0000000000000000
```

The instruction near the crash:

```
(b900003f)
```

On AArch64, this corresponds to a store instruction (`str`) writing to the address contained in `x1`.
Since `x1` is `0x0`, the driver attempts to write to address `0x0`.

This causes a **NULL pointer dereference**, resulting in a kernel oops.

---

## Conclusion

The `faulty` driver intentionally dereferences a NULL pointer inside `faulty_write()`, which causes the kernel to generate a data abort and crash. The oops information (PC, call trace, and register values) allows us to identify the exact failing function and confirm the NULL pointer write.
