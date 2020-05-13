function emit()
  return BPF.emit({
    -- Save callee saved register
    BPF.STX_MEM(BPF.DW, BPF.R10, BPF.R6, -8),
    BPF.STX_MEM(BPF.DW, BPF.R10, BPF.R7, -16),
    BPF.STX_MEM(BPF.DW, BPF.R10, BPF.R8, -24),
    BPF.STX_MEM(BPF.DW, BPF.R10, BPF.R9, -32),
    BPF.MOV64_IMM(BPF.R1, 0),
    BPF.MOV64_IMM(BPF.R2, 0),
    BPF.MOV64_IMM(BPF.R3, 0),
    BPF.MOV64_IMM(BPF.R4, 0),
    BPF.MOV64_IMM(BPF.R5, 0),
    BPF.MOV64_IMM(BPF.R6, 0),
    BPF.MOV64_IMM(BPF.R7, 0),
    BPF.MOV64_IMM(BPF.R8, 0),
    BPF.MOV64_IMM(BPF.R9, 0),
    -- Restore callee saved register
    BPF.LDX_MEM(BPF.DW, BPF.R6, BPF.R10, -8),
    BPF.LDX_MEM(BPF.DW, BPF.R7, BPF.R10, -16),
    BPF.LDX_MEM(BPF.DW, BPF.R8, BPF.R10, -24),
    BPF.LDX_MEM(BPF.DW, BPF.R9, BPF.R10, -32)
  })
end
