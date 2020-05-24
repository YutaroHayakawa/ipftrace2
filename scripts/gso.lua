-- SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
-- Copyright (C) 2020 Yutaro Hayakawa

-- Script to trace the behavior of the TSO/GSO, LRO/GRO.

GSO_FLAGS = {
  [ 1 << 0 ]  = "tcpv4",
  [ 1 << 1 ]  = "dodgy",
  [ 1 << 2 ]  = "tcp-ecn",
  [ 1 << 3 ]  = "tcp-fixedid",
  [ 1 << 4 ]  = "tcpv6",
  [ 1 << 5 ]  = "fcoe",
  [ 1 << 6 ]  = "gre",
  [ 1 << 7 ]  = "gre-csum",
  [ 1 << 8 ]  = "ipxip4",
  [ 1 << 9 ]  = "ipxip6",
  [ 1 << 10 ] = "udp-tunnel",
  [ 1 << 11 ] = "udp-tunnel-csum",
  [ 1 << 12 ] = "partial",
  [ 1 << 13 ] = "tunnel-remcsum",
  [ 1 << 14 ] = "sctp",
  [ 1 << 15 ] = "esp",
  [ 1 << 16 ] = "udp",
  [ 1 << 17 ] = "udp-l4",
  [ 1 << 18 ] = "flaglist",
}

function flags2str(flags)
  ret = ""
  is_first = true
  for k, v in pairs(GSO_FLAGS) do
    if flags & k ~=  0 then
      if not is_first then
        ret = ret.."|"..v
      else
        ret = ret..v
        is_first = false
      end
    end
  end
  return ret
end

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
  sp = 0  -- stack pointer, grows to negative direction
  dp = 0  -- data pointer, grows to positive direction

  ptr_size        = ipft.sizeof("uintptr_t")
  uint_size       = ipft.sizeof("unsigned int")
  skb_data_size   = ipft.sizeof("sk_buff_data_t")

  function push(size)
    sp = sp - size
    if sp < -256 then
      error("Stack overflow")
    end
    return sp
  end

  function pop(size)
    sp_orig = sp
    sp = sp + size
    if sp > 0 then
      error("Stack underflow")
    end
    return sp_orig
  end

  function push_data(size)
    dp_orig = dp
    dp = dp + size
    if dp > 64 then
      error("You cannot get more than 64bytes of data")
    end
    return dp_orig
  end

  --
  -- Emit the BPF code to read struct->member to memory. Since the generated
  -- code calls bpf_probe_read, caller saved registers (R0 - R5) will be
  -- invalidated after that.
  --
  -- Parameters
  -- struct  : Name of the struct (string)
  -- member  : Name of the member (string)
  -- reg     : Register that holds the pointer to the struct (BPF.R0 - BPF.R9)
  -- push_fn : Function to allocate memory (function)
  --
  -- Returns: eBPF binary string to read struct->member to memory (string)
  --
  function emit_member_read(struct, member, dst_reg, src_reg, push_fn)
    member_offset = ipft.offsetof(struct, member)
    member_size = ipft.sizeof(ipft.typeof(struct, member))
    return BPF.emit({
      BPF.MOV64_REG(BPF.R1, dst_reg),
      BPF.ALU64_IMM(BPF.ADD, BPF.R1, push_fn(member_size)),
      BPF.MOV64_IMM(BPF.R2, member_size),
      BPF.MOV64_REG(BPF.R3, src_reg),
      BPF.ALU64_IMM(BPF.ADD, BPF.R3, member_offset),
      BPF.CALL_INSN(BPF.FUNC.probe_read),
    })
  end

  function emit_save_callee_saved_registers()
    return BPF.emit({
      BPF.STX_MEM(BPF.DW, BPF.R10, BPF.R6, push(8)),
      BPF.STX_MEM(BPF.DW, BPF.R10, BPF.R7, push(8)),
      BPF.STX_MEM(BPF.DW, BPF.R10, BPF.R8, push(8)),
      BPF.STX_MEM(BPF.DW, BPF.R10, BPF.R9, push(8)),
    })
  end

  function emit_restore_callee_saved_registers()
    return BPF.emit({
      BPF.LDX_MEM(BPF.DW, BPF.R9, BPF.R10, pop(8)),
      BPF.LDX_MEM(BPF.DW, BPF.R8, BPF.R10, pop(8)),
      BPF.LDX_MEM(BPF.DW, BPF.R7, BPF.R10, pop(8)),
      BPF.LDX_MEM(BPF.DW, BPF.R6, BPF.R10, pop(8)),
    })
  end

  function emit_save_args()
    return BPF.emit({
      BPF.MOV64_REG(BPF.R6, BPF.R1), -- data
      BPF.MOV64_REG(BPF.R7, BPF.R2), -- ctx
      BPF.MOV64_REG(BPF.R8, BPF.R3), -- skb
    })
  end

  -- NET_SKBUFF_DATA_USES_OFFSET=y
  if skb_data_size == uint_size then
    return BPF.emit({
      -- Save callee saved registers
      emit_save_callee_saved_registers(),
      -- Keep register values for future use
      emit_save_args(),
      -- Get skb->head
      emit_member_read("sk_buff", "head", BPF.R10, BPF.R8, push),
      -- Get skb->end
      emit_member_read("sk_buff", "end", BPF.R10, BPF.R8, push),
      -- Get shinfo
      BPF.LDX_MEM(size2code(skb_data_size), BPF.R4, BPF.R10, pop(skb_data_size)),
      BPF.LDX_MEM(size2code(ptr_size), BPF.R3, BPF.R10, pop(ptr_size)),
      BPF.ALU64_REG(BPF.ADD, BPF.R3, BPF.R4),
      -- Save shinfo for future use
      BPF.MOV64_REG(BPF.R9, BPF.R3),
      -- Get skb->len
      emit_member_read("sk_buff", "len", BPF.R6, BPF.R8, push_data),
      -- Get shinfo->gso_size
      emit_member_read("skb_shared_info", "gso_size", BPF.R6, BPF.R9, push_data),
      -- Get shinfo->gso_segs
      emit_member_read("skb_shared_info", "gso_segs", BPF.R6, BPF.R9, push_data),
      -- Get shinfo->gso_type
      emit_member_read("skb_shared_info", "gso_segs", BPF.R6, BPF.R9, push_data),
      -- Restore callee saved registers
      emit_restore_callee_saved_registers(),
    })
  else
    error("Unsupported configuration. "..
          "Maybe your kernel is configured with NET_SKBUFF_DATA_USES_OFFSET=n")
  end
end

function dump(data)
  uint_size       = ipft.sizeof("unsigned int")
  ushort_size     = ipft.sizeof("short unsigned int")

  format = string.format("=I%dI%dI%dI%d", uint_size, ushort_size, ushort_size, uint_size)

  len, gso_size, gso_segs, gso_type = string.unpack(format, data)

  return string.format("(len: %d gso_size: %d gso_segs: %d gso_type: %s)",
                       len, gso_size, gso_segs, flags2str(gso_type))
end
