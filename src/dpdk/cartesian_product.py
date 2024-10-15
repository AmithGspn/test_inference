import itertools

# Example value-mask pairs for each field
field_a_pairs = [(0x1, 0xfffffffff)
, (0x2, 0xffffffffe)
, (0x4, 0xffffffffc)
, (0x8, 0xffffffff8)
, (0x10, 0xffffffff0)
, (0x20, 0xfffffffe0)
, (0x40, 0xfffffffc0)
, (0x80, 0xfffffffc0)
, (0xc0, 0xffffffff8)
, (0xc8, 0xfffffffff)]
field_b_pairs = [(0x1, 0xfffffffff)
, (0x2, 0xffffffffe)
, (0x4, 0xffffffffc)
, (0x8, 0xffffffff8)
, (0x10, 0xffffffff0)
, (0x20, 0xfffffffe0)
, (0x40, 0xfffffffc0)
, (0x80, 0xfffffff80)
, (0x100, 0xfffffff80)
, (0x180, 0xfffffffc0)
, (0x1c0, 0xfffffffe0)
, (0x1e0, 0xffffffff0)
, (0x1f0, 0xffffffffc)
, (0x1f4, 0xfffffffff)]

# Get Cartesian product of all value-mask pairs
combinations = itertools.product(field_a_pairs, field_b_pairs)

# Generate the P4 table add commands
for combination in combinations:
    value_a, mask_a = combination[0]
    value_b, mask_b = combination[1]
    command = f"match {hex(value_a)}/{hex(mask_a)} {hex(value_b)}/{hex(mask_b)} action forward_ternary dstAddr 0x1 port_id 0x0"
    print(command)