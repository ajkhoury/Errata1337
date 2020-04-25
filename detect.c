/**
 * LSTARHookDetect
 * Copyright (c) 2017-2020, Aidan Khoury. All rights reserved.
 *
 * @file detect.c
 * @author Aidan Khoury (ajkhoury)
 * @date 4/20/2020
 */

#include <wdm.h>
#include <intrin.h>

typedef ULONG_PTR UINTN;

//
// Define needed MSRs.
//

// Map of BASE Address of GS (R/W). If CPUID.80000001:EDX.[29] = 1.
#define MSR_GS_BASE 0xC0000101
// Swap Target of BASE Address of GS (R/W). If CPUID.80000001:EDX.[29] = 1.
#define MSR_KERNEL_GS_BASE 0xC0000102

//
// x86 Trap Interrupts/Exceptions.
//
// Intel SDM Vol. 3A - 6.15 EXCEPTION AND INTERRUPT REFERENCE
// AMD APM Vol. 2 r3.30 - 8.2 Vectors (Table 8-1. Interrupt Vector Source and Cause)
//
#define X86_TRAP_DE            0   // Divide Error (no error)
#define X86_TRAP_DB            1   // Debug trap (no error)
#define X86_TRAP_NMI           2   // Non-maskable Interrupt (no error)
#define X86_TRAP_BP            3   // Breakpoint Exception (INT3) (no error)
#define X86_TRAP_OF            4   // Overflow (INTO) (no error)
#define X86_TRAP_BR            5   // Bounds Range Exceeded (no error)
#define X86_TRAP_UD            6   // Undefined Opcode (no error)
#define X86_TRAP_NM            7   // No Math or Device not available (WAIT/FWAIT) (no error)
#define X86_TRAP_DF            8   // Double Fault (error)
#define X86_TRAP_OLD_MF        9   // 80x87 FP coprocessor operand fetch fault (no error)
#define X86_TRAP_TS            10  // Invalid TSS fault (error)
#define X86_TRAP_NP            11  // Segment Not Present (error)
#define X86_TRAP_SS            12  // Stack-segment Fault (error)
#define X86_TRAP_GP            13  // General Protection Fault (error)
#define X86_TRAP_PF            14  // Page Fault (error)
#define X86_TRAP_SPURIOUS      15  // Reserved/Spurious Interrupt
#define X86_TRAP_RESERVED      15  // Intel Reserved (error)
#define X86_TRAP_MF            16  // x87 Floating-Point Exception (no error)
#define X86_TRAP_AC            17  // Alignment check (error)
#define X86_TRAP_MC            18  // Machine Check (no error)
#define X86_TRAP_XF            19  // SIMD Floating-Point Exception (no error)
#define X86_TRAP_VE            20  // Intel Virtualization Exception (no error)
#define X86_TRAP_VC            29  // AMD VMM Communication Exception
#define X86_TRAP_SX            30  // AMD Security Exception
#define X86_TRAP_IRET          32  // IRET Exception

// SWAPGS instruction length is 3 bytes long.
#define SWAPGS_LENGTH 3

//
// Byte packed structure for an IDTR, GDTR, LDTR descriptor.
//
// Intel SDM Vol. 3A - 3.5.1 Segment Descriptor Tables (Figure 3-11. Pseudo-Descriptor Formats)
// AMD APM Vol. 2 r3.30 - 4.6.2 Global Descriptor-Table Register (Figure 4-8. GDTR and IDTR Format-Long Mode)
//
#include <pshpack1.h>
typedef struct _X64_DESCRIPTOR {
    UINT16 Limit;
    UINT64 Base;
} X64_DESCRIPTOR, *PX64_DESCRIPTOR;
#include <poppack.h>
C_ASSERT(FIELD_OFFSET(X64_DESCRIPTOR, Base) == 2);
C_ASSERT(sizeof(X64_DESCRIPTOR) == 10);

//
// Byte packed structure for an X64 Interrupt Gate Descriptor.
//
// Intel SDM Vol. 3A - 6.14.1 64-Bit Mode IDT (Figure 6-7. 64-Bit IDT Gate Descriptors)
// AMD APM Vol. 2 r3.30 - 4.8.4 Gate Descriptors (Figure 4-24. Interrupt-Gate and Trap-Gate Descriptors)
//
#pragma warning(push)
#pragma warning(disable:4214) // nonstandard extension used: bit field types other than int
#include <pshpack1.h>
typedef union _X64_IDT_GATE_DESCRIPTOR {
    struct _X64_IDT_GATE_DESCRIPTOR_BYTES {
        UINT16 OffsetLow;               // 0x00 Offset bits 15:0
        UINT16 Selector;                // 0x02 Segment Selector
        UINT8 IST;                      // 0x04 IST Interrupt Stack Table (first 3 bits)
        UINT8 TypeAttributes;           // 0x05 bits 3:0 Gate Type, then attributes.
        UINT16 OffsetMiddle;            // 0x06 Offset bits 31:16
        UINT32 OffsetHigh;              // 0x08 Offset bits 63:32
        UINT32 AlwaysZero;              // 0x0C Reserved (always zero)
    } Bytes;
    struct _X64_IDT_GATE_DESCRIPTOR_BITS {
        UINT16 OffsetLow;               // 0x00 Offset bits 15:0
        UINT16 Selector;                // 0x02 Segment Selector
        UINT8 IST : 3;                  // 0x04 IST Interrupt Stack Table
        UINT8 Reserved0 : 5;            // 0x04 Reserved (must be zero)
        UINT8 TYPE : 4;                 // 0x05 bits 3:0 Gate Type. See See the X86_DESC_TYPE_* defines.
        UINT8 S : 1;                    // 0x05 bit   4  S bit descriptor type flag (should always be zero!)
        UINT8 DPL : 2;                  // 0x05 bits 6:5 Descriptor privilege level
        UINT8 P : 1;                    // 0x05 bit   7  Present bit
        UINT16 OffsetMiddle;            // 0x06 Offset bits 31:16
        UINT64 OffsetHigh : 32;         // 0x08 Offset bits 63:32
        UINT64 AlwaysZero : 32;         // 0x0C Reserved (always zero)
    } Bits;
    UINT64 UInt64Low;                   // 0x00
    UINT64 UInt64High;                  // 0x08
} X64_IDT_GATE_DESCRIPTOR, *PX64_IDT_GATE_DESCRIPTOR;
#include <poppack.h>
#pragma warning(pop)
C_ASSERT(sizeof(X64_IDT_GATE_DESCRIPTOR) == 16);


//
// Processor Control Region Structure Definition
//
#pragma warning(push)
#pragma warning(disable:4201) // nonstandard extension used: nameless struct/union
typedef struct _KPCR {
    union {
        struct {
            union _KGDTENTRY64 *GdtBase;    // 0x00
            struct _KTSS64 *TssBase;        // 0x08
            UINT64 UserRsp;                 // 0x10
            struct _KPCR *Self;             // 0x18
            struct _KPRCB *CurrentPrcb;     // 0x20
            PKSPIN_LOCK_QUEUE LockArray;    // 0x28
            PVOID Used_Self;                // 0x30
        };
    };
    union {
        union _X64_IDT_GATE_DESCRIPTOR *IdtBase; // 0x38
        PVOID ProcessorDescriptorArea;      // 0x38
    };
    UINT64 Unused[2];                       // 0x40
    KIRQL Irql;                             // 0x50
    UINT8 SecondLevelCacheAssociativity;    // 0x51
    UINT8 ObsoleteNumber;                   // 0x52
    UINT8 Fill0;                            // 0x53
    UINT32 Unused0[3];                      // 0x54
    UINT16 MajorVersion;                    // 0x60
    UINT16 MinorVersion;                    // 0x62
    UINT32 StallScaleFactor;                // 0x64
    PVOID Unused1[3];                       // 0x68

    UINT32 KernelReserved[15];              // 0x80
    UINT32 SecondLevelCacheSize;            // 0xBC
    UINT32 HalReserved[16];                 // 0xC0
    UINT32 Unused2;                         // 0x100
    PVOID KdVersionBlock;                   // 0x108
    PVOID Unused3;                          // 0x110
    UINT32 PcrAlign1[24];                   // 0x118

//  struct _KPRCB Prcb;                     // 0x180

} KPCR, *PKPCR;
#pragma warning(pop)

//
// Get address of current processor block.
//

#define KeGetPcr() ((PKPCR)__readgsqword((unsigned long)FIELD_OFFSET(KPCR, Self)))

#define LOG_INFO(format, ...)   \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[INFO] " format, __VA_ARGS__)



UINTN KiErrata1337Present(VOID);
VOID FallbackHandler(VOID);
VOID PageFaultHandler(VOID);

_IRQL_requires_same_
_Function_class_(KIPI_BROADCAST_WORKER)
_IRQL_requires_(IPI_LEVEL)
UINTN
IpiBroadcastCallback(
    _In_ UINTN Argument
    )
{
    X64_IDT_GATE_DESCRIPTOR TempIdt[19];
    X64_DESCRIPTOR TempIdtr, OriginalIdtr;
    UINTN SyscallHandler;

    UNREFERENCED_PARAMETER(Argument);

    TempIdtr.Limit = sizeof(TempIdt)-1; // 0x12F
    TempIdtr.Base = (UINT64)&TempIdt[0];

    //
    // Copy needed interrupt handlers from original IDT.
    //
    TempIdt[X86_TRAP_DB] = KeGetPcr()->IdtBase[X86_TRAP_DB];
    TempIdt[X86_TRAP_NMI] = KeGetPcr()->IdtBase[X86_TRAP_NMI];
    TempIdt[X86_TRAP_GP] = KeGetPcr()->IdtBase[X86_TRAP_GP];
    TempIdt[X86_TRAP_PF] = KeGetPcr()->IdtBase[X86_TRAP_PF];
    TempIdt[X86_TRAP_MC] = KeGetPcr()->IdtBase[X86_TRAP_MC];

    //
    // Set handler addresses to fallback handler.
    //
    TempIdt[X86_TRAP_DB].Bytes.OffsetLow = (UINT16)(UINTN)FallbackHandler;
    TempIdt[X86_TRAP_DB].Bytes.OffsetMiddle = (UINT16)((UINTN)FallbackHandler >> 16);
    TempIdt[X86_TRAP_DB].Bytes.OffsetHigh = (UINT32)((UINTN)FallbackHandler >> 32);

    TempIdt[X86_TRAP_GP].Bytes.OffsetLow = (UINT16)(UINTN)FallbackHandler;
    TempIdt[X86_TRAP_GP].Bytes.OffsetMiddle = (UINT16)((UINTN)FallbackHandler >> 16);
    TempIdt[X86_TRAP_GP].Bytes.OffsetHigh = (UINT32)((UINTN)FallbackHandler >> 32);

    TempIdt[X86_TRAP_PF].Bytes.OffsetLow = (UINT16)(UINTN)FallbackHandler;
    TempIdt[X86_TRAP_PF].Bytes.OffsetMiddle = (UINT16)((UINTN)FallbackHandler >> 16);
    TempIdt[X86_TRAP_PF].Bytes.OffsetHigh = (UINT32)((UINTN)FallbackHandler >> 32);

    LOG_INFO("KernelGsBase = 0x%p", __readmsr(MSR_KERNEL_GS_BASE));
    LOG_INFO("GsBase = 0x%p", __readmsr(MSR_GS_BASE));

    _disable();
    __sidt(&OriginalIdtr);
    __lidt(&TempIdtr);

    //
    // Hook the PF handler in IDT.
    //
    TempIdt[X86_TRAP_PF].Bytes.OffsetLow = (UINT16)(UINTN)PageFaultHandler;
    TempIdt[X86_TRAP_PF].Bytes.OffsetMiddle = (UINT16)((UINTN)PageFaultHandler >> 16);
    TempIdt[X86_TRAP_PF].Bytes.OffsetHigh = (UINT32)((UINTN)PageFaultHandler >> 32);

    //
    // LET IT RIP!
    //
    SyscallHandler = KiErrata1337Present();

    __lidt(&OriginalIdtr);
    _enable();

    LOG_INFO("[#%d] SYSCALL handler = 0x%llX",
            KeGetCurrentProcessorNumberEx(NULL), SyscallHandler - SWAPGS_LENGTH);

    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(
    _In_ struct _DRIVER_OBJECT *DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    //
    // Run check on each CPU thread.
    //
    return (NTSTATUS)KeIpiGenericCall(IpiBroadcastCallback, 0);
}



