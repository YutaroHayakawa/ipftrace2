BPF = {}

-- Register
BPF.R0 = 0
BPF.R1 = 1
BPF.R2 = 2
BPF.R3 = 3
BPF.R4 = 4
BPF.R5 = 5
BPF.R6 = 6
BPF.R7 = 7
BPF.R8 = 8
BPF.R9 = 9
BPF.R10 = 10

-- Class
BPF.CLASS = function (code)
  return code & 0x07
end
BPF.LD    = 0x00
BPF.LDX   = 0x01
BPF.ST    = 0x02
BPF.STX   = 0x03
BPF.ALU   = 0x04
BPF.JMP   = 0x05
BPF.RET   = 0x06
BPF.MISC  = 0x07
BPF.JMP32 = 0x06
BPF.ALU64 = 0x07

-- Size
BPF.SIZE = function (code)
  return code & 0x18
end
BPF.W    = 0x00
BPF.H    = 0x08
BPF.B    = 0x10
BPF.DW   = 0x18
BPF.XADD = 0xc0

-- Mode
BPF.MODE = function (code)
  return code & 0xe0
end
BPF.IMM = 0x00
BPF.ABS = 0x20
BPF.IND = 0x40
BPF.MEM = 0x60
BPF.LEN = 0x80
BPF.MSH = 0xa0

-- ALU Operations
BPF.OP = function (code)
  return code & 0xf0
end
BPF.ADD  = 0x00
BPF.SUB  = 0x10
BPF.MUL  = 0x20
BPF.DIV  = 0x30
BPF.OR   = 0x40
BPF.AND  = 0x50
BPF.LSH  = 0x60
BPF.RSH  = 0x70
BPF.NEG  = 0x80
BPF.MOD  = 0x90
BPF.XOR  = 0xa0
BPF.MOV  = 0xb0
BPF.ARSH = 0xc0

-- JMP Operations
BPF.JA   = 0x00
BPF.JEQ  = 0x10
BPF.JGT  = 0x20
BPF.JGE  = 0x30
BPF.JSET = 0x40
BPF.JNE  = 0x50
BPF.JLT  = 0xa0
BPF.JLE  = 0xb0
BPF.JSGT = 0x60
BPF.JSGE = 0x70
BPF.JSLT = 0xc0
BPF.JSLE = 0xd0
BPF.CALL = 0x80
BPF.EXIT = 0x90

-- END Operations
BPF.END     = 0xd0
BPF.TO_LE   = 0x00
BPF.TO_BE   = 0x08
BPF.FROM_LE = BPF.TO_LE
BPF.FROM_BE = BPF.TO_BE

-- SRC
BPF.SRC = function (code)
  return code & 0x8
end
BPF.K = 0x00
BPF.X = 0x08

-- Helpers (can be used from kprobe program as of Linux 4.4)
BPF.FUNC = {}
BPF.FUNC.unspec = 0
BPF.FUNC.map_lookup_elem = 1
BPF.FUNC.map_update_elem = 2
BPF.FUNC.map_delete_elem = 3
BPF.FUNC.probe_read = 4
BPF.FUNC.ktime_getns = 5
BPF.FUNC.trace_printk = 6
BPF.FUNC.get_prandom_u32 = 7
BPF.FUNC.get_smp_processor_id = 8
BPF.FUNC.tail_call = 12
BPF.FUNC.get_current_pid_tgid = 14
BPF.FUNC.get_current_uid_gid = 15
BPF.FUNC.get_current_comm = 16
BPF.FUNC.perf_event_read = 22
BPF.FUNC.perf_event_output = 25

-- Function to emit instruction
local emit_protect = function (code, dst, src, off, imm)
  return string.pack("I1I1i2i4", code, src << 4 | dst, off, imm)
end

local emit = function (code, dst, src, off, imm)
  ok, ret = pcall(emit_protect, code, dst, src, off, imm)
  if (ok) then
    return ret
  else
    errmsg = debug.traceback("\nemit(code:"..tostring(code)..", dst: "..
             tostring(dst)..", src: "..tostring(src)..", off: "..tostring(off)..", imm: "..
             tostring(imm)..")")
    error(errmsg)
  end
end

-- Opcodes
BPF.ALU64_REG = function (op, dst, src)
  return emit(BPF.ALU64 | BPF.OP(op) | BPF.X, dst, src, 0, 0)
end

BPF.ALU32_REG = function (op, dst, src)
  return emit(BPF.ALU | BPF.OP(op) | BPF.X, dst, src, 0, 0)
end

BPF.ALU64_IMM = function (op, dst, imm)
  return emit(BPF.ALU64 | BPF.OP(op) | BPF.K, dst, 0, 0, imm)
end

BPF.ALU32_IMM = function (op, dst, imm)
  return emit(BPF.ALU | BPF.OP(op) | BPF.K, dst, 0, 0, imm)
end

BPF.ENDIAN = function (t, dst, len)
  return emit(BPF.ALU | BPF.END | BPF.SRC(t), dst, 0, 0, len)
end

BPF.MOV64_REG = function (dst, src)
  return emit(BPF.ALU64 | BPF.MOV | BPF.X, dst, src, 0, 0)
end

BPF.MOV32_REG = function (dst, src)
  return emit(BPF.ALU | BPF.MOV | BPF.X, dst, src, 0, 0)
end

BPF.MOV64_IMM = function (dst, imm)
  return emit(BPF.ALU64 | BPF.MOV | BPF.K, dst, 0, 0, imm)
end

BPF.MOV_IMM = function (dst, imm)
  return emit(BPF.ALU | BPF.MOV | BPF.K, dst, 0, 0, imm)
end

BPF.LD_IMM64 = function (dst, imm)
  return emit(BPF.LD | BPF.DW | BPF.IMM, dst, 0, 0, imm & 0x00000000ffffffff)..
         emit(0, 0, 0, 0, imm >> 32)
end

BPF.LDX_MEM = function (size, dst, src, off)
  return emit(BPF.LDX | BPF.SIZE(size) | BPF.MEM, dst, src, off, 0)
end

BPF.STX_MEM = function (size, dst, src, off)
  return emit(BPF.STX | BPF.SIZE(size) | BPF.MEM, dst, src, off, 0)
end

BPF.STX_XADD = function (size, dst, src, off)
  return emit(BPF.STX | BPF.SIZE(size) | BPF.XADD, dst, src, off, 0)
end

BPF.ST_MEM = function (size, dst, off, imm)
  return emit(BPF.ST | BPF.SIZE(size) | BPF.MEM, dst, 0, off, imm)
end

BPF.JMP_REG = function (op, dst, src, off)
  return emit(BPF.JMP | BPF.OP(op) | BPF.X, dst, src, off, 0)
end

BPF.JMP_IMM = function (op, dst, imm, off)
  return emit(BPF.JMP | BPF.OP(op) | BPF.K, dst, 0, off, imm)
end

BPF.JMP32_REG = function (op, dst, src, off)
  return emit(BPF.JMP32 | BPF.OP(op) | BPF.X, dst, src, off, 0)
end

BPF.JMP32_IMM = function (op, dst, imm, off)
  return emit(BPF.JMP32 | BPF.OP(op) | BPF.K, dst, 0, off, imm)
end

BPF.JMP_A = function (off)
  return emit(BPF.JMP | BPF.JA, 0, 0, off, 0)
end

BPF.CALL_INSN = function (helper_id)
  return emit(BPF.JMP | BPF.CALL, 0, 0, 0, helper_id)
end

BPF.EXIT_INSN = function ()
  return emit(BPF.JMP | BPF.EXIT, 0, 0, 0, 0)
end

BPF.RAW_INSN = function (code, dst, src, off, imm)
  return emit(code, dst, src, off, imm)
end

BPF.emit = function (insns)
  ret = ""
  for i = 1, #insns, 1 do
    ret = ret..insns[i]
  end
  return ret
end
