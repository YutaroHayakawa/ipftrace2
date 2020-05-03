uint_size       = ipft_sizeof("unsigned int")
ushort_size     = ipft_sizeof("short unsigned int")
ptr_size        = ipft_sizeof("uintptr_t")
skb_data_size   = ipft_sizeof("sk_buff_data_t")
len_offset      = ipft_offsetof("sk_buff", "len")
head_offset     = ipft_offsetof("sk_buff", "head")
end_offset      = ipft_offsetof("sk_buff", "end")
gso_size_offset = ipft_offsetof("skb_shared_info", "gso_size")
gso_segs_offset = ipft_offsetof("skb_shared_info", "gso_segs")
gso_type_offset = ipft_offsetof("skb_shared_info", "gso_type")

function size2code(size)
  if size == 1 then
    return BPF.B
  elseif size == 2 then
    return BPF.H
  elseif size == 4 then
    return BPF.W
  elseif size == 8 then
    return BPF.DW
  else
    error(string.format("Cannot convert size %d to eBPF code", size))
  end
end

function emit()
  if skb_data_size == uint_size then
    return BPF.emit({
      -- Save callee saved registers
      BPF.STX_MEM(BPF.DW, BPF.R10, BPF.R6, -8),
      BPF.STX_MEM(BPF.DW, BPF.R10, BPF.R7, -16),
      BPF.STX_MEM(BPF.DW, BPF.R10, BPF.R8, -24),
      BPF.STX_MEM(BPF.DW, BPF.R10, BPF.R9, -32),
      -- Keep register values for future use
      BPF.MOV64_REG(BPF.R6, BPF.R1), -- trace->data
      BPF.MOV64_REG(BPF.R7, BPF.R2), -- ctx
      BPF.MOV64_REG(BPF.R8, BPF.R3), -- skb
      -- Get skb->head
      BPF.MOV64_REG(BPF.R1, BPF.R10),
      BPF.ALU64_IMM(BPF.ADD, BPF.R1, -32 - ptr_size),
      BPF.MOV64_IMM(BPF.R2, ptr_size),
      BPF.ALU64_IMM(BPF.ADD, BPF.R3, head_offset),
      BPF.CALL_INSN(BPF.FUNC.probe_read),
      -- Get skb->end
      BPF.MOV64_REG(BPF.R1, BPF.R10),
      BPF.ALU64_IMM(BPF.ADD, BPF.R1, -32 - ptr_size - skb_data_size),
      BPF.MOV64_IMM(BPF.R2, skb_data_size),
      BPF.MOV64_REG(BPF.R3, BPF.R8),
      BPF.ALU64_IMM(BPF.ADD, BPF.R3, end_offset),
      BPF.CALL_INSN(BPF.FUNC.probe_read),
      -- Get shinfo
      BPF.LDX_MEM(size2code(ptr_size), BPF.R3, BPF.R10, -32 - ptr_size),
      BPF.LDX_MEM(size2code(skb_data_size), BPF.R4, BPF.R10, -32 - ptr_size - skb_data_size),
      BPF.ALU64_REG(BPF.ADD, BPF.R3, BPF.R4),
      -- Save shinfo for future use
      BPF.MOV64_REG(BPF.R9, BPF.R3),
      -- Get skb->len
      BPF.MOV64_REG(BPF.R1, BPF.R6),
      BPF.MOV64_IMM(BPF.R2, uint_size),
      BPF.MOV64_REG(BPF.R3, BPF.R8),
      BPF.ALU64_IMM(BPF.ADD, BPF.R3, len_offset),
      BPF.CALL_INSN(BPF.FUNC.probe_read),
      -- Get shinfo->gso_size
      BPF.MOV64_REG(BPF.R1, BPF.R6),
      BPF.ALU64_IMM(BPF.ADD, BPF.R1, uint_size),
      BPF.MOV64_IMM(BPF.R2, ushort_size),
      BPF.MOV64_REG(BPF.R3, BPF.R9),
      BPF.ALU64_IMM(BPF.ADD, BPF.R3, gso_size_offset),
      BPF.CALL_INSN(BPF.FUNC.probe_read),
      -- Get shinfo->gso_segs
      BPF.MOV64_REG(BPF.R1, BPF.R6),
      BPF.ALU64_IMM(BPF.ADD, BPF.R1, uint_size + ushort_size),
      BPF.MOV64_IMM(BPF.R2, ushort_size),
      BPF.MOV64_REG(BPF.R3, BPF.R9),
      BPF.ALU64_IMM(BPF.ADD, BPF.R3, gso_segs_offset),
      BPF.CALL_INSN(BPF.FUNC.probe_read),
      -- Get shinfo->gso_type
      BPF.MOV64_REG(BPF.R1, BPF.R6),
      BPF.ALU64_IMM(BPF.ADD, BPF.R1, uint_size + ushort_size + ushort_size),
      BPF.MOV64_IMM(BPF.R2, uint_size),
      BPF.MOV64_REG(BPF.R3, BPF.R9),
      BPF.ALU64_IMM(BPF.ADD, BPF.R3, gso_type_offset),
      BPF.CALL_INSN(BPF.FUNC.probe_read),
      -- Restore callee saved registers
      BPF.LDX_MEM(BPF.DW, BPF.R6, BPF.R10, -8),
      BPF.LDX_MEM(BPF.DW, BPF.R7, BPF.R10, -16),
      BPF.LDX_MEM(BPF.DW, BPF.R8, BPF.R10, -24),
      BPF.LDX_MEM(BPF.DW, BPF.R9, BPF.R10, -32),
    })
  end
end

function dump(data)
  format = string.format("=I%dI%dI%dI%d", uint_size, ushort_size, ushort_size, uint_size)
  len, gso_size, gso_segs, gso_type = string.unpack(format, data)
  return string.format("(len: %d size: %d segs: %d type: 0x%x)", len, gso_size, gso_segs, gso_type)
end
