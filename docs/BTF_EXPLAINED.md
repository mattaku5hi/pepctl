# BTF (BPF Type Format) Explained

## What is BTF?

**BTF (BPF Type Format)** is a metadata format that encodes debug information for BPF programs. It provides type information about data structures, function signatures, and other program elements that the kernel and userspace tools need to understand and interact with eBPF programs safely.

## Why Does eBPF Need BTF?

### 1. **Type Safety and Verification**
- The eBPF verifier uses BTF information to ensure type safety
- Prevents accessing invalid memory locations or using incorrect data types
- Enables compile-time and runtime type checking

### 2. **CO-RE (Compile Once - Run Everywhere)**
- BTF enables portable eBPF programs that work across different kernel versions
- Programs can adapt to different kernel data structure layouts automatically
- Eliminates the need to recompile eBPF programs for each kernel version

### 3. **Debugging and Introspection**
- Tools like `bpftool` can display human-readable information about eBPF programs
- Enables better debugging experience with meaningful variable and structure names
- Allows runtime inspection of eBPF program state

### 4. **Map Value Type Information**
- BTF describes the layout of values stored in eBPF maps
- Enables userspace programs to correctly interpret map data
- Supports complex data structures in maps

## BTF Sections Explained

### `.BTF` Section
```
Purpose: Core type information
Content: Type definitions, structure layouts, function signatures
Size: Variable (depends on program complexity)
```

**What it contains:**
- **Primitive types**: `int`, `char`, `void`, etc.
- **Composite types**: `struct`, `union`, `enum`
- **Function signatures**: Parameter types and return types
- **Array and pointer types**: Type relationships
- **Type modifiers**: `const`, `volatile`, `restrict`

**Example BTF type information:**
```c
// Original C code
struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

// BTF encodes this as:
// Type ID 1: struct packet_info
//   Member 0: src_ip, type=__u32, offset=0
//   Member 1: dst_ip, type=__u32, offset=4
//   Member 2: src_port, type=__u16, offset=8
//   Member 3: dst_port, type=__u16, offset=10
//   Member 4: protocol, type=__u8, offset=12
```

### `.BTF.ext` Section
```
Purpose: Extended debugging information
Content: Line information, function information, relocation data
Size: Variable (depends on debug info)
```

**What it contains:**
- **Line information**: Maps eBPF instructions to source code lines
- **Function information**: Function entry points and metadata
- **Relocation information**: How to resolve external references
- **Variable location information**: Where variables are stored

**Benefits:**
- Enables source-level debugging of eBPF programs
- Provides meaningful stack traces and error messages
- Supports profiling and performance analysis tools

### `.rel.BTF` Section
```
Purpose: BTF relocation information
Content: Relocation entries for BTF data
Size: Small (relocation table)
```

**What it contains:**
- Relocation entries that tell the loader how to fix up BTF references
- Address adjustments needed when loading the program
- Symbol resolution information

### `.rel.BTF.ext` Section
```
Purpose: BTF extended information relocations
Content: Relocation entries for BTF.ext data
Size: Small (relocation table)
```

**What it contains:**
- Relocations for line number information
- Function address adjustments
- Debug symbol relocations

## BTF in Action: PEPCTL Example

### Before BTF (Error):
```
libbpf: BTF is required, but is missing or corrupted.
[error] [pepctl] [EBPF] libbpf operation failed
```

### After BTF (Success):
```bash
# Check BTF sections
$ readelf -S packet_filter.o | grep BTF
[17] .BTF              PROGBITS         0000000000000000  00001664
[18] .rel.BTF          REL              0000000000000000  00003910
[19] .BTF.ext          PROGBITS         0000000000000000  00002424
[20] .rel.BTF.ext      REL              0000000000000000  00003940
```

### BTF Information Inspection:
```bash
# View BTF information
$ bpftool btf dump file packet_filter.o

# View program information with BTF
$ bpftool prog show
$ bpftool prog dump xlated id <prog_id>
```

## Compilation Flags for BTF

### Required Flags:
```cmake
# Enable debug information (includes BTF)
-g

# Target BPF architecture
-target bpf

# Optimization (required for eBPF)
-O2
```

### Flags to Avoid:
```cmake
# These disable debug information and BTF
-fno-debug-info-for-profiling  # ❌ Removes debug info
-fno-dwarf2-cfi-asm           # ❌ Disables DWARF info
-g0                           # ❌ No debug info
```

## BTF and Kernel Compatibility

### Kernel Requirements:
- **Linux 4.18+**: Basic BTF support
- **Linux 5.2+**: BTF for maps
- **Linux 5.4+**: Full CO-RE support
- **Linux 5.8+**: BTF for modules

### Checking System BTF Support:
```bash
# Check if kernel has BTF
ls -la /sys/kernel/btf/vmlinux

# Check BTF ID
cat /sys/kernel/btf/vmlinux | head -c 4 | xxd
```

## Common BTF Issues and Solutions

### Issue 1: Missing BTF
```
Error: BTF is required, but is missing or corrupted
Solution: Add -g flag to compilation
```

### Issue 2: Corrupted BTF
```
Error: Invalid BTF format
Solution: Rebuild with correct clang version (10+)
```

### Issue 3: BTF Size Limits
```
Error: BTF too large
Solution: Reduce program complexity or split into multiple programs
```

## BTF Tools and Utilities

### `bpftool btf`
```bash
# Dump BTF information
bpftool btf dump file program.o

# Show kernel BTF
bpftool btf dump file /sys/kernel/btf/vmlinux

# Format as C headers
bpftool btf dump file program.o format c
```

### `pahole`
```bash
# Show structure layouts with BTF
pahole -J program.o

# Compare structures between versions
pahole --btf_encode_detached vmlinux
```

## Performance Impact

### BTF Overhead:
- **Compile time**: +10-20% (debug info generation)
- **Binary size**: +20-50% (type information)
- **Runtime**: Minimal (only during load/verification)
- **Memory**: Small (BTF cached in kernel)

### Benefits vs. Cost:
```
✅ Type safety and verification
✅ Better debugging experience  
✅ CO-RE portability
✅ Tool integration
❌ Larger binary size
❌ Slightly longer compilation
```

## Best Practices

### 1. Always Enable BTF in Production
```cmake
# Production eBPF compilation
set(EBPF_COMPILE_FLAGS
    -O2
    -target bpf
    -g              # ✅ Enable BTF
    -D__KERNEL__
    # ... other flags
)
```

### 2. Validate BTF Information
```bash
# Verify BTF sections exist
readelf -S program.o | grep BTF

# Validate BTF format
bpftool btf dump file program.o > /dev/null
```

### 3. Use BTF-Aware Tools
```bash
# Use bpftool for inspection
bpftool prog show
bpftool map show

# Use BTF for debugging
gdb with eBPF BTF support
```

## Conclusion

BTF is essential for modern eBPF development, providing:
- **Type safety** through verification
- **Portability** via CO-RE
- **Debuggability** with rich metadata
- **Tool integration** for better development experience

While BTF adds some compilation overhead, the benefits far outweigh the costs, making it a critical component of any production eBPF program.

---

*For more information about eBPF and BTF, see the [Linux kernel BPF documentation](https://www.kernel.org/doc/html/latest/bpf/index.html).* 