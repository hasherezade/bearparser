#pragma once

#include "../win_hdrs/win_types.h"
#if _MSC_VER
#define USE_WINNT
#include <windows.h>
#include <winnt.h>
#endif

/*
 * Directory Entries
 */
 //additional : WIN_CERTIFICATE
 //additional : VS_VERSIONINFO

#ifndef USE_WINNT

#ifndef UNALIGNED
#define UNALIGNED
#endif

/*
 * Platform independent definitions
 *
 * following values are the accepted values of these signatures;
 * their serialization/deserialization should be handled by memio.h
 * primitives when required
 */

/*
 * Platform independent definitions (for gcc, vxd, sys ...)
 *
 * following values are the accepted values of these signatures;
 * their serialization/deserialization should be handled by memio.h
 * primitives when required
 */

#include "../win_hdrs/pshpack4.h"                   // 4 byte packing is the default
#include "../win_hdrs/pshpack2.h"                   // 16 bit headers are 2 byte packed

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER, IMG_DOS_HEADER;

typedef struct _IMAGE_OS2_HEADER {      // OS/2 .EXE header
    WORD   ne_magic;                    // 00 Magic number
    CHAR   ne_ver;                      // 02 Version number
    CHAR   ne_rev;                      // 03 Revision number
    WORD   ne_enttab;                   // 04 Offset of Entry Table
    WORD   ne_cbenttab;                 // 06 Number of bytes in Entry Table
    LONG   ne_crc;                      // 08 Checksum of whole file
    WORD   ne_flags;                    // 0c Flag word
    WORD   ne_autodata;                 // 0e Automatic data segment number
    WORD   ne_heap;                     // 10 Initial heap allocation
    WORD   ne_stack;                    // 12 Initial stack allocation
    LONG   ne_csip;                     // 14 Initial CS:IP setting
    LONG   ne_sssp;                     // 18 Initial SS:SP setting
    WORD   ne_cseg;                     // 1c Count of file segments
    WORD   ne_cmod;                     // 1e Entries in Module Reference Table
    WORD   ne_cbnrestab;                // 20 Size of non-resident name table
    WORD   ne_segtab;                   // 22 Offset of Segment Table
    WORD   ne_rsrctab;                  // 24 Offset of Resource Table
    WORD   ne_restab;                   // 26 Offset of resident name table
    WORD   ne_modtab;                   // 28 Offset of Module Reference Table
    WORD   ne_imptab;                   // 2a Offset of Imported Names Table
    LONG   ne_nrestab;                  // 2c Offset of Non-resident Names Table
    WORD   ne_cmovent;                  // 30 Count of movable entries
    WORD   ne_align;                    // 32 Segment alignment shift count
    WORD   ne_cres;                     // 34 Count of resource segments
    BYTE   ne_exetyp;                   // 36 Target Operating system
    BYTE   ne_flagsothers;              // 37 Other .EXE flags
    WORD   ne_pretthunks;               // 38 offset to return thunks
    WORD   ne_psegrefbytes;             // 3a offset to segment ref. bytes
    WORD   ne_swaparea;                 // 3c Minimum code swap area size
    WORD   ne_expver;                   // 3e Expected Windows version number
} IMAGE_OS2_HEADER, *PIMAGE_OS2_HEADER;

typedef struct _IMAGE_VXD_HEADER {      // Windows VXD header
    WORD   e32_magic;                   // Magic number
    BYTE   e32_border;                  // The byte ordering for the VXD
    BYTE   e32_worder;                  // The word ordering for the VXD
    DWORD  e32_level;                   // The EXE format level for now = 0
    WORD   e32_cpu;                     // The CPU type
    WORD   e32_os;                      // The OS type
    DWORD  e32_ver;                     // Module version
    DWORD  e32_mflags;                  // Module flags
    DWORD  e32_mpages;                  // Module # pages
    DWORD  e32_startobj;                // Object # for instruction pointer
    DWORD  e32_eip;                     // Extended instruction pointer
    DWORD  e32_stackobj;                // Object # for stack pointer
    DWORD  e32_esp;                     // Extended stack pointer
    DWORD  e32_pagesize;                // VXD page size
    DWORD  e32_lastpagesize;            // Last page size in VXD
    DWORD  e32_fixupsize;               // Fixup section size
    DWORD  e32_fixupsum;                // Fixup section checksum
    DWORD  e32_ldrsize;                 // Loader section size
    DWORD  e32_ldrsum;                  // Loader section checksum
    DWORD  e32_objtab;                  // Object table offset
    DWORD  e32_objcnt;                  // Number of objects in module
    DWORD  e32_objmap;                  // Object page map offset
    DWORD  e32_itermap;                 // Object iterated data map offset
    DWORD  e32_rsrctab;                 // Offset of Resource Table
    DWORD  e32_rsrccnt;                 // Number of resource entries
    DWORD  e32_restab;                  // Offset of resident name table
    DWORD  e32_enttab;                  // Offset of Entry Table
    DWORD  e32_dirtab;                  // Offset of Module Directive Table
    DWORD  e32_dircnt;                  // Number of module directives
    DWORD  e32_fpagetab;                // Offset of Fixup Page Table
    DWORD  e32_frectab;                 // Offset of Fixup Record Table
    DWORD  e32_impmod;                  // Offset of Import Module Name Table
    DWORD  e32_impmodcnt;               // Number of entries in Import Module Name Table
    DWORD  e32_impproc;                 // Offset of Import Procedure Name Table
    DWORD  e32_pagesum;                 // Offset of Per-Page Checksum Table
    DWORD  e32_datapage;                // Offset of Enumerated Data Pages
    DWORD  e32_preload;                 // Number of preload pages
    DWORD  e32_nrestab;                 // Offset of Non-resident Names Table
    DWORD  e32_cbnrestab;               // Size of Non-resident Name Table
    DWORD  e32_nressum;                 // Non-resident Name Table Checksum
    DWORD  e32_autodata;                // Object # for automatic data object
    DWORD  e32_debuginfo;               // Offset of the debugging information
    DWORD  e32_debuglen;                // The length of the debugging info. in bytes
    DWORD  e32_instpreload;             // Number of instance pages in preload section of VXD file
    DWORD  e32_instdemand;              // Number of instance pages in demand load section of VXD file
    DWORD  e32_heapsize;                // Size of heap - for 16-bit apps
    BYTE   e32_res3[12];                // Reserved words
    DWORD  e32_winresoff;
    DWORD  e32_winreslen;
    WORD   e32_devid;                   // Device ID for VxD
    WORD   e32_ddkver;                  // DDK version for VxD
} IMAGE_VXD_HEADER, *PIMAGE_VXD_HEADER;

#include "../win_hdrs/poppack.h"                    // Back to 4 byte packing

/*
 * File header format.
 */

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

enum file {
    F_RELOCS_STRIPPED = 0x0001, // Relocation info stripped from file.
    F_EXECUTABLE_IMAGE = 0x0002,  // File is executable  (i.e. no unresolved external references).
    F_LINE_NUMS_STRIPPED = 0x0004,  // Line numbers stripped from file.
    F_LOCAL_SYMS_STRIPPED = 0x0008,  // Local symbols stripped from file.
    F_AGGRESIVE_WS_TRIM = 0x0010,  // Aggressively trim working set
    F_LARGE_ADDRESS_AWARE = 0x0020,  // App can handle >2gb addresses
    F_BYTES_REVERSED_LO = 0x0080,  // Bytes of machine word are reversed.
    F_MACHINE_32BIT = 0x0100,  // 32 bit word machine.
    F_DEBUG_STRIPPED = 0x0200,  // Debugging info stripped from file in .DBG file
    F_REMOVABLE_RUN_FROM_SWAP = 0x0400,  // If Image is on removable media, copy and run from the swap file.
    F_NET_RUN_FROM_SWAP = 0x0800,  // If Image is on Net, copy and run from the swap file.
    F_SYSTEM = 0x1000,  // System File.
    F_DLL = 0x2000,  // File is a DLL.
    F_UP_SYSTEM_ONLY = 0x4000,  // File should only be run on a UP machine
    F_BYTES_REVERSED_HI = 0x8000  // Bytes of machine word are reversed.
};

enum file_machine {
    M_UNKNOWN = 0,
    M_I386 = 0x014c,  // Intel 386.
    M_R3000 = 0x0162,  // MIPS little-endian, 0x160 big-endian
    M_R4000 = 0x0166,  // MIPS little-endian
    M_R10000 = 0x0168,  // MIPS little-endian
    M_WCEMIPSV2 = 0x0169,  // MIPS little-endian WCE v2
    M_ALPHA = 0x0184,  // Alpha_AXP
    M_SH3 = 0x01a2,  // SH3 little-endian
    M_SH3DSP = 0x01a3,
    M_SH3E = 0x01a4,  // SH3E little-endian
    M_SH4 = 0x01a6,  // SH4 little-endian
    M_SH5 = 0x01a8,  // SH5
    M_ARM = 0x01c0,  // ARM Little-Endian
    M_THUMB = 0x01c2,
    M_AM33 = 0x01d3,
    M_POWERPC = 0x01F0,  // IBM PowerPC Little-Endian
    M_POWERPCFP = 0x01f1,
    M_IA64 = 0x0200,  // Intel 64
    M_MIPS16 = 0x0266,  // MIPS
    M_ALPHA64 = 0x0284,  // ALPHA64
    M_MIPSFPU = 0x0366,  // MIPS
    M_MIPSFPU16 = 0x0466,  // MIPS
    M_AXP64 = M_ALPHA64,
    M_TRICORE = 0x0520,  // Infineon
    M_CEF = 0x0CEF,
    M_EBC = 0x0EBC,  // EFI Byte Code
    M_AMD64 = 0x8664,  // AMD64 (K8)
    M_M32R = 0x9041,  // M32R little-endian
    M_CEE = 0xC0EE
};

/*
 * Directory format.
 */
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
#endif

#define DIRECTORY_ENTRIES_NUM 16

#ifndef USE_WINNT

/*
 * Optional header format.
 */

typedef struct _IMAGE_OPTIONAL_HEADER {
/*
 * Standard fields.
 */
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
/*
 * NT additional fields.
 */
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[DIRECTORY_ENTRIES_NUM];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
    WORD   Magic;
    BYTE   MajorLinkerVersion;
    BYTE   MinorLinkerVersion;
    DWORD  SizeOfCode;
    DWORD  SizeOfInitializedData;
    DWORD  SizeOfUninitializedData;
    DWORD  AddressOfEntryPoint;
    DWORD  BaseOfCode;
    DWORD  BaseOfData;
    DWORD  BaseOfBss;
    DWORD  GprMask;
    DWORD  CprMask[4];
    DWORD  GpValue;
} IMAGE_ROM_OPTIONAL_HEADER, *PIMAGE_ROM_OPTIONAL_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[DIRECTORY_ENTRIES_NUM];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64, PE_IMAGE_NT_HEADERS64, *PE_PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32, PE_IMAGE_NT_HEADERS32, *PE_PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_ROM_HEADERS {
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
} IMAGE_ROM_HEADERS, *PIMAGE_ROM_HEADERS;

#define PE_FIRST_SECTION64( ntheader ) ((PE_PIMAGE_SECTION_HEADER)    \
    ((UINT_PTR)ntheader +    \
     FIELD_OFFSET( PE_IMAGE_NT_HEADERS64, OptionalHeader ) +    \
     ((PE_PIMAGE_NT_HEADERS64)(ntheader))->FileHeader.SizeOfOptionalHeader    \
    ))

#define PE_FIRST_SECTION32( ntheader ) ((PE_PIMAGE_SECTION_HEADER)    \
    ((UINT_PTR)ntheader +    \
     FIELD_OFFSET( PE_IMAGE_NT_HEADERS32, OptionalHeader ) +    \
     ((PE_PIMAGE_NT_HEADERS32)(ntheader))->FileHeader.SizeOfOptionalHeader    \
    ))

/*
 * Non-COFF Object file header
 */
#if 0
// XXX disabled for now, due to CLSID type inconsistency
typedef struct ANON_OBJECT_HEADER {
    WORD    Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
    WORD    Sig2;            // Must be 0xffff
    WORD    Version;         // >= 1 (implies the CLSID field is present)
    WORD    Machine;
    DWORD   TimeDateStamp;
    CLSID   ClassID;         // Used to invoke CoCreateInstance
    DWORD   SizeOfData;      // Size of data that follows the header
} ANON_OBJECT_HEADER;

typedef struct ANON_OBJECT_HEADER_V2 {
    WORD    Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
    WORD    Sig2;            // Must be 0xffff
    WORD    Version;         // >= 2 (implies the Flags field is present - otherwise V1)
    WORD    Machine;
    DWORD   TimeDateStamp;
    CLSID   ClassID;         // Used to invoke CoCreateInstance
    DWORD   SizeOfData;      // Size of data that follows the header
    DWORD   Flags;           // 0x1 -> contains metadata
    DWORD   MetaDataSize;    // Size of CLR metadata
    DWORD   MetaDataOffset;  // Offset of CLR metadata
} ANON_OBJECT_HEADER_V2;
#endif

/*
 * Section header format.
 */
#define SHORT_NAME_SIZE 8

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[SHORT_NAME_SIZE];
    union {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER, PE_IMAGE_SECTION_HEADER, *PE_PIMAGE_SECTION_HEADER;

#define IMAGE_SECTION_HEADER_SIZE 40

/*
 * Section characteristics.
 */
enum section_charact
{
    //      IMAGE_SCN_TYPE_REG =    0x00000000,  // Reserved.
    //      IMAGE_SCN_TYPE_DSECT =  0x00000001,  // Reserved.
    //      IMAGE_SCN_TYPE_NOLOAD = 0x00000002,  // Reserved.
    //      IMAGE_SCN_TYPE_GROUP =  0x00000004,  // Reserved.
    SCN_TYPE_NO_PAD = 0x00000008,  // Reserved.
    //      IMAGE_SCN_TYPE_COPY =   0x00000010,  // Reserved.
    SCN_CNT_CODE =  0x00000020,  // Section contains code.
    SCN_CNT_INITIALIZED_DATA =  0x00000040,  // Section contains initialized data.
    SCN_CNT_UNINITIALIZED_DATA =   0x00000080,  // Section contains uninitialized data.
    SCN_LNK_OTHER = 0x00000100,  // Reserved.
    SCN_LNK_INFO = 0x00000200,  // Section contains comments or some other type of information.
    //      IMAGE_SCN_TYPE_OVER = 0x00000400,  // Reserved.
    SCN_LNK_REMOVE = 0x00000800,  // Section contents will not become part of image.
    SCN_LNK_COMDAT = 0x00001000,  // Section contents comdat.
    //          0x00002000,  // Reserved.
    //      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
    SCN_NO_DEFER_SPEC_EXC = 0x00004000,  // Reset speculative exceptions handling bits in the TLB entries for this section.
    SCN_GPREL = 0x00008000,  // Section content can be accessed relative to GP
    SCN_MEM_FARDATA = 0x00008000,
    //      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
    SCN_MEM_PURGEABLE = 0x00020000,
    SCN_MEM_16BIT = 0x00020000,
    SCN_MEM_LOCKED = 0x00040000,
    SCN_MEM_PRELOAD = 0x00080000,
    SCN_ALIGN_1BYTES = 0x00100000,  //
    SCN_ALIGN_2BYTES = 0x00200000,  //
    SCN_ALIGN_4BYTES = 0x00300000,  //
    SCN_ALIGN_8BYTES = 0x00400000,  //
    SCN_ALIGN_16BYTES = 0x00500000,  // Default alignment if no others are specified.
    SCN_ALIGN_32BYTES = 0x00600000,  //
    SCN_ALIGN_64BYTES = 0x00700000,  //
    SCN_ALIGN_128BYTES = 0x00800000,  //
    SCN_ALIGN_256BYTES = 0x00900000,  //
    SCN_ALIGN_512BYTES = 0x00A00000,  //
    SCN_ALIGN_1024BYTES = 0x00B00000,  //
    SCN_ALIGN_2048BYTES = 0x00C00000,  //
    SCN_ALIGN_4096BYTES = 0x00D00000,  //
    SCN_ALIGN_8192BYTES = 0x00E00000,  //
    // Unused  0x00F00000
    SCN_LNK_NRELOC_OVFL = 0x01000000,  // Section contains extended relocations.
    SCN_MEM_DISCARDABLE = 0x02000000,  // Section can be discarded.
    SCN_MEM_NOT_CACHED =  0x04000000,  // Section is not cachable.
    SCN_MEM_NOT_PAGED = 0x08000000,  // Section is not pageable.
    SCN_MEM_SHARED =  0x10000000,  // Section is shareable.
    SCN_MEM_EXECUTE = 0x20000000,  // Section is executable.
    SCN_MEM_READ =  0x40000000,  // Section is readable.
    SCN_MEM_WRITE = 0x80000000, // Section is writeable.
    SCN_SCALE_INDEX = 0x00000001  // Tls index is scaled
};

#include "../win_hdrs/pshpack2.h"                       // Symbols, relocs, and linenumbers are 2 byte packed

/*
 * Symbol format
 */
typedef struct _IMAGE_SYMBOL {
    union {
        BYTE    ShortName[8];
        struct {
            DWORD   Short;     // if 0, use LongName
            DWORD   Long;      // offset into string table
        } Name;
        DWORD   LongName[2];    // PBYTE [2]
    } N;
    DWORD   Value;
    SHORT   SectionNumber;
    WORD    Type;
    BYTE    StorageClass;
    BYTE    NumberOfAuxSymbols;
} IMAGE_SYMBOL;

typedef IMAGE_SYMBOL UNALIGNED *PIMAGE_SYMBOL;

#define IMAGE_SYMBOL_SIZE 18

/*
 * Section values.
 *
 * Symbols have a section number of the section in which they are
 * defined. Otherwise, section numbers have the following meanings:
 */
enum symbol {
    SYM_UNDEFINED = (SHORT)0 ,         // Symbol is undefined or is common.
    SYM_ABSOLUTE = (SHORT)-1,    // Symbol is an absolute value.
    SYM_DEBUG = (SHORT)-2,        // Symbol is a special debug item.
    SYM_SECTION_MAX = 0xFEFF            // Values 0xFF00-0xFFFF are special
};

/*
 * Type (fundamental) values.
 */
enum symbol_type {
    SYMT_NULL =   0x0000,  // no type.
    SYMT_VOID =   0x0001,  //
    SYMT_CHAR =   0x0002,  // type character.
    SYMT_SHORT =  0x0003,  // type short integer.
    SYMT_INT =    0x0004,  //
    SYMT_LONG =   0x0005,  //
    SYMT_FLOAT =  0x0006,  //
    SYMT_DOUBLE = 0x0007,  //
    SYMT_STRUCT = 0x0008,  //
    SYMT_UNION =  0x0009,  //
    SYMT_ENUM =   0x000A,  // enumeration.
    SYMT_MOE =    0x000B,  // member of enumeration.
    SYMT_BYTE =   0x000C,  //
    SYMT_WORD =   0x000D,  //
    SYMT_UINT =   0x000E,  //
    SYMT_DWORD =  0x000F,  //
    SYMT_PCODE =  0x8000      //
};

/*
 * Type (derived) values
 */
enum symbol_dtype {
    SYMDT_NULL =     0,       // no derived type.
    SYMDT_POINTER =  1,       // pointer.
    SYMDT_FUNCTION = 2,       // function.
    SYMDT_ARRAY =    3       // array.
};

/*
 * Storage classes.
 */
enum symbol_class {
    SYMC_END_OF_FUNCTION = (BYTE )-1,
    SYMC_NULL = 0x0000,
    SYMC_AUTOMATIC  =    0x0001,
    SYMC_EXTERNAL  = 0x0002,
    SYMC_STATIC =  0x0003,
    SYMC_REGISTER = 0x0004,
    SYMC_EXTERNAL_DEF = 0x0005,
    SYMC_LABEL  =   0x0006,
    SYMC_UNDEFINED_LABEL =  0x0007,
    SYMC_MEMBER_OF_STRUCT = 0x0008,
    SYMC_ARGUMENT  = 0x0009,
    SYMC_STRUCT_TAG  =   0x000A,
    SYMC_MEMBER_OF_UNION =  0x000B,
    SYMC_UNION_TAG  =    0x000C,
    SYMC_TYPE_DEFINITION =  0x000D,
    SYMC_UNDEFINED_STATIC = 0x000E,
    SYMC_ENUM_TAG  = 0x000F,
    SYMC_MEMBER_OF_ENUM =   0x0010,
    SYMC_REGISTER_PARAM =   0x0011,
    SYMC_BIT_FIELD  =  0x0012,

    SYMC_FAR_EXTERNAL = 0x0044,  //

    SYMC_BLOCK  =  0x0064,
    SYMC_FUNCTION  =  0x0065,
    SYMC_END_OF_STRUCT =  0x0066,
    SYMC_FILE = 0x0067,
    // new
    SYMC_SECTION  = 0x0068,
    SYMC_WEAK_EXTERNAL =    0x0069,
    SYMC_CLR_TOKEN  =    0x006B
};

/*
 * type packing constants
 */
enum packing {
    PCK_BTMASK = 0x000F,
    PCK_TMASK = 0x0030,
    PCK_TMASK1 = 0x00C0,
    PCK_TMASK2 = 0x00F0,
    PCK_BTSHFT = 4,
    PCK_TSHIFT = 2
};


/*
 * Auxiliary entry format.
 */
typedef union _IMAGE_AUX_SYMBOL {
    struct {
        DWORD    TagIndex;                      // struct, union, or enum tag index
        union {
            struct {
                WORD    Linenumber;             // declaration line number
                WORD    Size;                   // size of struct, union, or enum
            } LnSz;
            DWORD    TotalSize;
        } Misc;
        union {
            struct {                            // if ISFCN, tag, or .bb
                DWORD    PointerToLinenumber;
                DWORD    PointerToNextFunction;
            } Function;
            struct {                            // if ISARY, up to 4 dimen.
                WORD     Dimension[4];
            } sArray;        // Array -> sArray  RJ
        } FcnAry;
        WORD    TvIndex;                        // tv index
    } Sym;
    struct {
        BYTE    Name[IMAGE_SYMBOL_SIZE];
    } File;
    struct {
        DWORD   Length;                         // section length
        WORD    NumberOfRelocations;            // number of relocation entries
        WORD    NumberOfLinenumbers;            // number of line numbers
        DWORD   CheckSum;                       // checksum for communal
        SHORT   Number;                         // section number to associate with
        BYTE    Selection;                      // communal selection type
    } Section;
} IMAGE_AUX_SYMBOL;
typedef IMAGE_AUX_SYMBOL UNALIGNED *PIMAGE_AUX_SYMBOL;

typedef enum IMAGE_AUX_SYMBOL_TYPE {
    IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1,
} IMAGE_AUX_SYMBOL_TYPE;

#include "../win_hdrs/pshpack2.h"

typedef struct IMAGE_AUX_SYMBOL_TOKEN_DEF {
    BYTE  bAuxType;                  // IMAGE_AUX_SYMBOL_TYPE
    BYTE  bReserved;                 // Must be 0
    DWORD SymbolTableIndex;
    BYTE  rgbReserved[12];           // Must be 0
} IMAGE_AUX_SYMBOL_TOKEN_DEF;

typedef IMAGE_AUX_SYMBOL_TOKEN_DEF UNALIGNED *PIMAGE_AUX_SYMBOL_TOKEN_DEF;

#include "../win_hdrs/poppack.h"

/*
 * Communal selection types.
 */
enum comdat_select {
    SEL_NODUPLICATES = 1,
    SEL_ANY = 2,
    SEL_SAME_SIZE = 3,
    SEL_EXACT_MATCH = 4,
    SEL_ASSOCIATIVE = 5,
    SEL_LARGEST = 6,
    SEL_NEWEST = 7
};

enum weak_ext_srch {
    SRCH_NOLIBRARY = 1,
    SRCH_LIBRARY = 2,
    SRCH_ALIAS = 3
};

/*
 * Relocation format.
 */
typedef struct _IMAGE_RELOCATION {
    union {
        DWORD   VirtualAddress;
        DWORD   RelocCount;             // Set to the real count when IMAGE_SCN_LNK_NRELOC_OVFL is set
    };
    DWORD   SymbolTableIndex;
    WORD    Type;
} IMAGE_RELOCATION;
typedef IMAGE_RELOCATION UNALIGNED *PIMAGE_RELOCATION;

/*
 * I386 relocation types.
 */
enum reloc_type {
    REL_I386_ABSOLUTE = 0x0000,  // Reference is absolute, no relocation is necessary
    REL_I386_DIR16 = 0x0001,  // Direct 16-bit reference to the symbols virtual address
    REL_I386_REL16 = 0x0002,  // PC-relative 16-bit reference to the symbols virtual address
    REL_I386_DIR32 = 0x0006,  // Direct 32-bit reference to the symbols virtual address
    REL_I386_DIR32NB = 0x0007,  // Direct 32-bit reference to the symbols virtual address, base not included
    REL_I386_SEG12 = 0x0009,  // Direct 16-bit reference to the segment-selector bits of a 32-bit virtual address
    REL_I386_SECTION = 0x000A,
    REL_I386_SECREL = 0x000B,
    REL_I386_TOKEN = 0x000C,  // clr token
    REL_I386_SECREL7 = 0x000D,  // 7 bit offset from base of section containing target
    REL_I386_REL32 = 0x0014,  // PC-relative 32-bit reference to the symbols virtual address
/*
 * MIPS relocation types.
 */
    REL_MIPS_ABSOLUTE = 0x0000,  // Reference is absolute, no relocation is necessary
    REL_MIPS_REFHALF =  0x0001,
    REL_MIPS_REFWORD =  0x0002,
    REL_MIPS_JMPADDR =  0x0003,
    REL_MIPS_REFHI = 0x0004,
    REL_MIPS_REFLO = 0x0005,
    REL_MIPS_GPREL =  0x0006,
    REL_MIPS_LITERAL = 0x0007,
    REL_MIPS_SECTION = 0x000A,
    REL_MIPS_SECREL = 0x000B,
    REL_MIPS_SECRELLO = 0x000C,  // Low 16-bit section relative referemce (used for >32k TLS)
    REL_MIPS_SECRELHI = 0x000D,  // High 16-bit section relative reference (used for >32k TLS)
    REL_MIPS_TOKEN = 0x000E,  // clr token
    REL_MIPS_JMPADDR16 = 0x0010,
    REL_MIPS_REFWORDNB = 0x0022,
    REL_MIPS_PAIR = 0x0025,
/*
 * Alpha Relocation types.
 */
    REL_ALPHA_ABSOLUTE = 0x0000,
    REL_ALPHA_REFLONG = 0x0001,
    REL_ALPHA_REFQUAD = 0x0002,
    REL_ALPHA_GPREL32 = 0x0003,
    REL_ALPHA_LITERAL = 0x0004,
    REL_ALPHA_LITUSE = 0x0005,
    REL_ALPHA_GPDISP = 0x0006,
    REL_ALPHA_BRADDR = 0x0007,
    REL_ALPHA_HINT = 0x0008,
    REL_ALPHA_INLINE_REFLONG = 0x0009,
    REL_ALPHA_REFHI = 0x000A,
    REL_ALPHA_REFLO = 0x000B,
    REL_ALPHA_PAIR = 0x000C,
    REL_ALPHA_MATCH = 0x000D,
    REL_ALPHA_SECTION = 0x000E,
    REL_ALPHA_SECREL = 0x000F,
    REL_ALPHA_REFLONGNB = 0x0010,
    REL_ALPHA_SECRELLO = 0x0011,  // Low 16-bit section relative reference
    REL_ALPHA_SECRELHI = 0x0012, // High 16-bit section relative reference
    REL_ALPHA_REFQ3 = 0x0013,  // High 16 bits of 48 bit reference
    REL_ALPHA_REFQ2 = 0x0014,  // Middle 16 bits of 48 bit reference
    REL_ALPHA_REFQ1 = 0x0015,  // Low 16 bits of 48 bit reference
    REL_ALPHA_GPRELLO = 0x0016,  // Low 16-bit GP relative reference
    REL_ALPHA_GPRELHI = 0x0017,  // High 16-bit GP relative reference
/*
 * IBM PowerPC relocation types.
 */
    REL_PPC_ABSOLUTE = 0x0000,  // NOP
    REL_PPC_ADDR64 =   0x0001,  // 64-bit address
    REL_PPC_ADDR32 =   0x0002,  // 32-bit address
    REL_PPC_ADDR24 =   0x0003,  // 26-bit address, shifted left 2 (branch absolute)
    REL_PPC_ADDR16 =   0x0004,  // 16-bit address
    REL_PPC_ADDR14 =   0x0005,  // 16-bit address, shifted left 2 (load doubleword)
    REL_PPC_REL24 =    0x0006,  // 26-bit PC-relative offset, shifted left 2 (branch relative)
    REL_PPC_REL14 =    0x0007,  // 16-bit PC-relative offset, shifted left 2 (br cond relative)
    REL_PPC_TOCREL16 = 0x0008,  // 16-bit offset from TOC base
    REL_PPC_TOCREL14 = 0x0009,  // 16-bit offset from TOC base, shifted left 2 (load doubleword)

    REL_PPC_ADDR32NB = 0x000A,  // 32-bit addr w/o image base
    REL_PPC_SECREL =   0x000B,  // va of containing section (as in an image sectionhdr)
    REL_PPC_SECTION =  0x000C,  // sectionheader number
    REL_PPC_IFGLUE =   0x000D,  // substitute TOC restore instruction iff symbol is glue code
    REL_PPC_IMGLUE =   0x000E,  // symbol is glue code; virtual address is TOC restore instruction
    REL_PPC_SECREL16 = 0x000F,  // va of containing section (limited to 16 bits)
    REL_PPC_REFHI =    0x0010,
    REL_PPC_REFLO =    0x0011,
    REL_PPC_PAIR =     0x0012,
    REL_PPC_SECRELLO = 0x0013,  // Low 16-bit section relative reference (used for >32k TLS)
    REL_PPC_SECRELHI = 0x0014,  // High 16-bit section relative reference (used for >32k TLS)
    REL_PPC_GPREL =    0x0015,
    REL_PPC_TOKEN =    0x0016,  // clr token

    REL_PPC_TYPEMASK = 0x00FF,  // mask to isolate above values in IMAGE_RELOCATION.Type
/*
 * Flag bits in IMAGE_RELOCATION.TYPE
 */
    REL_PPC_NEG = 0x0100,  // subtract reloc value rather than adding it
    REL_PPC_BRTAKEN =  0x0200,  // fix branch prediction bit to predict branch taken
    REL_PPC_BRNTAKEN = 0x0400,  // fix branch prediction bit to predict branch not taken
    REL_PPC_TOCDEFN =  0x0800,  // toc slot defined in file (or, data in toc)
/*
 * Hitachi SH3 relocation types.
 */
    REL_SH3_ABSOLUTE = 0x0000,  // No relocation
    REL_SH3_DIRECT16 = 0x0001,  // 16 bit direct
    REL_SH3_DIRECT32 = 0x0002,  // 32 bit direct
    REL_SH3_DIRECT8 = 0x0003,  // 8 bit direct, -128..255
    REL_SH3_DIRECT8_WORD = 0x0004,  // 8 bit direct .W (0 ext.)
    REL_SH3_DIRECT8_LONG = 0x0005,  // 8 bit direct .L (0 ext.)
    REL_SH3_DIRECT4 = 0x0006,  // 4 bit direct (0 ext.)
    REL_SH3_DIRECT4_WORD = 0x0007,  // 4 bit direct .W (0 ext.)
    REL_SH3_DIRECT4_LONG = 0x0008,  // 4 bit direct .L (0 ext.)
    REL_SH3_PCREL8_WORD = 0x0009,  // 8 bit PC relative .W
    REL_SH3_PCREL8_LONG = 0x000A,  // 8 bit PC relative .L
    REL_SH3_PCREL12_WORD = 0x000B,  // 12 LSB PC relative .W
    REL_SH3_STARTOF_SECTION = 0x000C,  // Start of EXE section
    REL_SH3_SIZEOF_SECTION = 0x000D,  // Size of EXE section
    REL_SH3_SECTION = 0x000E,  // Section table index
    REL_SH3_SECREL = 0x000F,  // Offset within section
    REL_SH3_DIRECT32_NB = 0x0010,  // 32 bit direct not based
    REL_SH3_GPREL4_LONG = 0x0011,  // GP-relative addressing
    REL_SH3_TOKEN = 0x0012,  // clr token
/*
 * SHM
 */
    REL_SHM_PCRELPT = 0x0013,  // Offset from current instruction in longwords if not NOMODE, insert the inverse of the low bit at bit 32 to select PTA/PTB
    REL_SHM_REFLO = 0x0014,  // Low bits of 32-bit address
    REL_SHM_REFHALF = 0x0015,  // High bits of 32-bit address
    REL_SHM_RELLO = 0x0016,  // Low bits of relative reference
    REL_SHM_RELHALF =  0x0017,  // High bits of relative reference
    REL_SHM_PAIR = 0x0018,  // offset operand for relocation
/*
 * SH
 */
    REL_SH_NOMODE = 0x8000,  // relocation ignores section mode
/*
 * ARM
 */
    REL_ARM_ABSOLUTE = 0x0000,  // No relocation required
    REL_ARM_ADDR32 =   0x0001,  // 32 bit address
    REL_ARM_ADDR32NB = 0x0002,  // 32 bit address w/o image base
    REL_ARM_BRANCH24 = 0x0003,  // 24 bit offset << 2 & sign ext.
    REL_ARM_BRANCH11 = 0x0004,  // Thumb: 2 11 bit offsets
    REL_ARM_TOKEN =    0x0005,  // clr token
    REL_ARM_GPREL12 =  0x0006,  // GP-relative addressing (ARM)
    REL_ARM_GPREL7 =   0x0007,  // GP-relative addressing (Thumb)
    REL_ARM_BLX24 =    0x0008,
    REL_ARM_BLX11 =    0x0009,
    REL_ARM_SECTION =  0x000E,  // Section table index
    REL_ARM_SECREL =   0x000F,  // Offset within section
/*
 * AM
 */
    REL_AM_ABSOLUTE = 0x0000,
    REL_AM_ADDR32 =   0x0001,
    REL_AM_ADDR32NB = 0x0002,
    REL_AM_CALL32 =   0x0003,
    REL_AM_FUNCINFO = 0x0004,
    REL_AM_REL32_1 =  0x0005,
    REL_AM_REL32_2 =  0x0006,
    REL_AM_SECREL =   0x0007,
    REL_AM_SECTION =  0x0008,
    REL_AM_TOKEN =    0x0009,
/*
 * x64 relocations
 */
    REL_AMD64_ABSOLUTE = 0x0000,  // Reference is absolute, no relocation is necessary
    REL_AMD64_ADDR64 =   0x0001,  // 64-bit address (VA).
    REL_AMD64_ADDR32 =   0x0002,  // 32-bit address (VA).
    REL_AMD64_ADDR32NB = 0x0003,  // 32-bit address w/o image base (RVA).
    REL_AMD64_REL32 =    0x0004,  // 32-bit relative address from byte following reloc
    REL_AMD64_REL32_1 =  0x0005,  // 32-bit relative address from byte distance 1 from reloc
    REL_AMD64_REL32_2 =  0x0006,  // 32-bit relative address from byte distance 2 from reloc
    REL_AMD64_REL32_3 =  0x0007,  // 32-bit relative address from byte distance 3 from reloc
    REL_AMD64_REL32_4 =  0x0008,  // 32-bit relative address from byte distance 4 from reloc
    REL_AMD64_REL32_5 =  0x0009,  // 32-bit relative address from byte distance 5 from reloc
    REL_AMD64_SECTION =  0x000A,  // Section index
    REL_AMD64_SECREL =   0x000B,  // 32 bit offset from base of section containing target
    REL_AMD64_SECREL7 =  0x000C,  // 7 bit unsigned offset from base of section containing target
    REL_AMD64_TOKEN =    0x000D,  // 32 bit metadata token
    REL_AMD64_SREL32 =   0x000E,  // 32 bit signed span-dependent value emitted into object
    REL_AMD64_PAIR =     0x000F,
    REL_AMD64_SSPAN32 =  0x0010,  // 32 bit signed span-dependent value applied at link time
/*
 * IA64 relocation types.
 */
    REL_IA64_ABSOLUTE =  0x0000,
    REL_IA64_IMM14 = 0x0001,
    REL_IA64_IMM22 = 0x0002,
    REL_IA64_IMM64 = 0x0003,
    REL_IA64_DIR32 = 0x0004,
    REL_IA64_DIR64 = 0x0005,
    REL_IA64_PCREL21B = 0x0006,
    REL_IA64_PCREL21M = 0x0007,
    REL_IA64_PCREL21F = 0x0008,
    REL_IA64_GPREL22 = 0x0009,
    REL_IA64_LTOFF22 = 0x000A,
    REL_IA64_SECTION = 0x000B,
    REL_IA64_SECREL22 = 0x000C,
    REL_IA64_SECREL64I = 0x000D,
    REL_IA64_SECREL32 = 0x000E,
    //REL_IA64_LTOFF64 = 0x000F
    REL_IA64_DIR32NB = 0x0010,
    REL_IA64_SREL14 = 0x0011,
    REL_IA64_SREL22 = 0x0012,
    REL_IA64_SREL32 = 0x0013,
    REL_IA64_UREL32 = 0x0014,
    REL_IA64_PCREL60X = 0x0015,  // This is always a BRL and never converted
    REL_IA64_PCREL60B = 0x0016,  // If possible, convert to MBB bundle with NOP.B in slot 1
    REL_IA64_PCREL60F = 0x0017,  // If possible, convert to MFB bundle with NOP.F in slot 1
    REL_IA64_PCREL60I = 0x0018,  // If possible, convert to MIB bundle with NOP.I in slot 1
    REL_IA64_PCREL60M = 0x0019,  // If possible, convert to MMB bundle with NOP.M in slot 1
    REL_IA64_IMMGPREL64 = 0x001A,
    REL_IA64_TOKEN = 0x001B,  // clr token
    REL_IA64_GPREL32 = 0x001C,
    REL_IA64_ADDEND = 0x001F,
/*
 * CEF relocation types.
 */
    REL_CEF_ABSOLUTE = 0x0000,  // Reference is absolute, no relocation is necessary
    REL_CEF_ADDR32 = 0x0001,  // 32-bit address (VA).
    REL_CEF_ADDR64 = 0x0002,  // 64-bit address (VA).
    REL_CEF_ADDR32NB = 0x0003,  // 32-bit address w/o image base (RVA).
    REL_CEF_SECTION = 0x0004,  // Section index
    REL_CEF_SECREL = 0x0005,  // 32 bit offset from base of section containing target
    REL_CEF_TOKEN =  0x0006,  // 32 bit metadata token
/*
 * clr relocation types.
 */
    REL_CEE_ABSOLUTE = 0x0000,  // Reference is absolute, no relocation is necessary
    REL_CEE_ADDR32 = 0x0001,  // 32-bit address (VA).
    REL_CEE_ADDR64 = 0x0002,  // 64-bit address (VA).
    REL_CEE_ADDR32NB = 0x0003,  // 32-bit address w/o image base (RVA).
    REL_CEE_SECTION =  0x0004,  // Section index
    REL_CEE_SECREL = 0x0005,  // 32 bit offset from base of section containing target
    REL_CEE_TOKEN = 0x0006,  // 32 bit metadata token
/*
 * M32R
 */
    REL_M32R_ABSOLUTE = 0x0000,  // No relocation required
    REL_M32R_ADDR32 =   0x0001,  // 32 bit address
    REL_M32R_ADDR32NB = 0x0002,  // 32 bit address w/o image base
    REL_M32R_ADDR24 =   0x0003,  // 24 bit address
    REL_M32R_GPREL16 =  0x0004,  // GP relative addressing
    REL_M32R_PCREL24 =  0x0005,  // 24 bit offset << 2 & sign ext.
    REL_M32R_PCREL16 =  0x0006,  // 16 bit offset << 2 & sign ext.
    REL_M32R_PCREL8 =   0x0007,  // 8 bit offset << 2 & sign ext.
    REL_M32R_REFHALF =  0x0008,  // 16 MSBs
    REL_M32R_REFHI =    0x0009,  // 16 MSBs; adj for LSB sign ext.
    REL_M32R_REFLO =    0x000A,  // 16 LSBs
    REL_M32R_PAIR =     0x000B,  // Link HI and LO
    REL_M32R_SECTION =  0x000C,  // Section table index
    REL_M32R_SECREL32 = 0x000D,  // 32 bit section relative reference
    REL_M32R_TOKEN =    0x000E,  // clr token
/*
 * EBC
 */
    REL_EBC_ABSOLUTE = 0x0000, // No relocation required
    REL_EBC_ADDR32NB = 0x0001,  // 32 bit address w/o image base
    REL_EBC_REL32 =   0x0002,  // 32-bit relative address from byte following reloc
    REL_EBC_SECTION = 0x0003,  // Section table index
    REL_EBC_SECREL =  0x0004  // Offset within section
};

/* Intel-IA64-Fillers */
#define IMM64_EXT(Value, Address, Size, InstPos, ValPos)             \
    Value |= (((ULONGLONG)((*(Address) >> InstPos) & (((ULONGLONG)1 << Size) - 1))) << ValPos)

#define IMM64_INS(Value, Address, Size, InstPos, ValPos)  \
    *(PDWORD)Address = (*(PDWORD)Address & ~(((1 << Size) - 1) << InstPos)) | \
    ((DWORD)((((ULONGLONG)Value >> ValPos) & (((ULONGLONG)1 << Size) - 1))) << InstPos)


enum emarch_enc117 {
    IMM7B_INST_WORD_X = 3,  // Intel-IA64-Filler
    IMM7B_SIZE_X = 7,  // Intel-IA64-Filler
    IMM7B_INST_WORD_POS_X = 4,  // Intel-IA64-Filler
    IMM7B_VAL_POS_X = 0,  // Intel-IA64-Filler

    IMM9D_INST_WORD_X = 3,  // Intel-IA64-Filler
    IMM9D_SIZE_X = 9,  // Intel-IA64-Filler
    IMM9D_INST_WORD_POS_X = 18, // Intel-IA64-Filler
    IMM9D_VAL_POS_X = 7,  // Intel-IA64-Filler

    IMMSC_INST_WORD_X = 3,  // Intel-IA64-Filler
    IMMSC_SIZE_X = 5,  // Intel-IA64-Filler
    IMMSC_INST_WORD_POS_X = 13, // Intel-IA64-Filler
    IMMSC_VAL_POS_X = 16, // Intel-IA64-Filler

    IC_INST_WORD_X =  3, // Intel-IA64-Filler
    IC_SIZE_X =  1, // Intel-IA64-Filler
    IC_INST_WORD_POS_X = 12, // Intel-IA64-Filler
    IC_VAL_POS_X = 21, // Intel-IA64-Filler

    IMM41A_INST_WORD_X = 1,// Intel-IA64-Filler
    IMM41A_SIZE_X = 10, // Intel-IA64-Filler
    IMM41A_INST_WORD_POS_X = 14, // Intel-IA64-Filler
    IMM41A_VAL_POS_X = 22, // Intel-IA64-Filler

    IMM41B_INST_WORD_X = 1, // Intel-IA64-Filler
    IMM41B_SIZE_X = 8, // Intel-IA64-Filler
    IMM41B_INST_WORD_POS_X = 24, // Intel-IA64-Filler
    IMM41B_VAL_POS_X = 32, // Intel-IA64-Filler

    IMM41c_INST_WORD_X = 2, // Intel-IA64-Filler
    IMM41c_SIZE_X =  23, // Intel-IA64-Filler
    IMM41c_INST_WORD_POS_X =  0, // Intel-IA64-Filler
    IMM41c_VAL_POS_X = 40, // Intel-IA64-Filler

    SIGN_INST_WORD_X =   3, // Intel-IA64-Filler
    SIGN_SIZE_X = 1,// Intel-IA64-Filler
    SIGN_INST_WORD_POS_X = 27,// Intel-IA64-Filler
    SIGN_VAL_POS_X = 63 // Intel-IA64-Filler
};


enum x3 {
    OPCODE_INST_WORD_X =3,  // Intel-IA64-Filler
    OPCODE_SIZE_X =4,  // Intel-IA64-Filler
    OPCODE_INST_WORD_POS_X = 28, // Intel-IA64-Filler
    OPCODE_SIGN_VAL_POS_X =  0,  // Intel-IA64-Filler

    I_INST_WORD_X = 3,  // Intel-IA64-Filler
    I_SIZE_X = 1,  // Intel-IA64-Filler
    I_INST_WORD_POS_X = 27, // Intel-IA64-Filler
    I_SIGN_VAL_POS_X =  59, // Intel-IA64-Filler

    D_WH_INST_WORD_X =  3,  // Intel-IA64-Filler
    D_WH_SIZE_X =  3,  // Intel-IA64-Filler
    D_WH_INST_WORD_POS_X = 24, // Intel-IA64-Filler
    D_WH_SIGN_VAL_POS_X = 0,  // Intel-IA64-Filler

    IMM20_INST_WORD_X = 3,  // Intel-IA64-Filler
    IMM20_SIZE_X = 20, // Intel-IA64-Filler
    IMM20_INST_WORD_POS_X =  4,  // Intel-IA64-Filler
    IMM20_SIGN_VAL_POS_X =   0,  // Intel-IA64-Filler

    IMM39_1_INST_WORD_X =    2,  // Intel-IA64-Filler
    IMM39_1_SIZE_X =    23, // Intel-IA64-Filler
    IMM39_1_INST_WORD_POS_X  = 0,  // Intel-IA64-Filler
    IMM39_1_SIGN_VAL_POS_X = 36, // Intel-IA64-Filler

    IMM39_2_INST_WORD_X =    1,  // Intel-IA64-Filler
    IMM39_2_SIZE_X =    16, // Intel-IA64-Filler
    IMM39_2_INST_WORD_POS_X = 16, // Intel-IA64-Filler
    IMM39_2_SIGN_VAL_POS_X = 20, // Intel-IA64-Filler

    P_INST_WORD_X =3,  // Intel-IA64-Filler
    P_SIZE_X =  4,  // Intel-IA64-Filler
    P_INST_WORD_POS_X = 0,  // Intel-IA64-Filler
    P_SIGN_VAL_POS_X =  0,  // Intel-IA64-Filler

    TMPLT_INST_WORD_X = 0,  // Intel-IA64-Filler
    TMPLT_SIZE_X = 4,  // Intel-IA64-Filler
    TMPLT_INST_WORD_POS_X =  0,  // Intel-IA64-Filler
    TMPLT_SIGN_VAL_POS_X =   0,  // Intel-IA64-Filler

    BTYPE_QP_INST_WORD_X = 2,  // Intel-IA64-Filler
    BTYPE_QP_SIZE_X =  9,  // Intel-IA64-Filler
    BTYPE_QP_INST_WORD_POS_X = 23, // Intel-IA64-Filler
    BTYPE_QP_INST_VAL_POS_X  = 0,  // Intel-IA64-Filler

    EMPTY_INST_WORD_X = 1,  // Intel-IA64-Filler
    EMPTY_SIZE_X = 2,  // Intel-IA64-Filler
    EMPTY_INST_WORD_POS_X = 14, // Intel-IA64-Filler
    EMPTY_INST_VAL_POS_X = 0  // Intel-IA64-Filler
};

/*
 * Line number format.
 */
typedef struct _IMAGE_LINENUMBER {
    union {
        DWORD   SymbolTableIndex;               // Symbol table index of function name if Linenumber is 0.
        DWORD   VirtualAddress;                 // Virtual address of line number.
    } Type;
    WORD    Linenumber;                         // Line number.
} IMAGE_LINENUMBER;
typedef IMAGE_LINENUMBER UNALIGNED *PIMAGE_LINENUMBER;

#include "../win_hdrs/poppack.h"                        // Back to 4 byte packing

/*
 * Based relocation format.
 */
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
    /*  WORD    TypeOffset[1]; */
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;

/*
 * Based relocation types.
 */
enum reloc_based {
    RELB_ABSOLUTE = 0,
    RELB_HIGH = 1,
    RELB_LOW = 2,
    RELB_HIGHLOW = 3,
    RELB_HIGHADJ = 4,
    RELB_MIPS_JMPADDR = 5,
    RELB_SECTION = 6,
    RELB_REL32 =  7,
    RELB_MIPS_JMPADDR16 = 9,
    RELB_IA64_IMM64 = 9,
    RELB_DIR64 =  10,
    RELB_HIGH3ADJ = 11
};


/*
 * Archive format
 */
#define ARCHIVE_START_SIZE             8
#define ARCHIVE_START                  "!<arch>\n"
#define ARCHIVE_END                    "`\n"
#define ARCHIVE_PAD                    "\n"
#define ARCHIVE_LINKER_MEMBER          "/               "
#define ARCHIVE_LONGNAMES_MEMBER       "//              "

typedef struct _IMAGE_ARCHIVE_MEMBER_HEADER {
    BYTE     Name[16];                          // File member name - `/' terminated.
    BYTE     Date[12];                          // File member date - decimal.
    BYTE     UserID[6];                         // File member user id - decimal.
    BYTE     GroupID[6];                        // File member group id - decimal.
    BYTE     Mode[8];                           // File member mode - octal.
    BYTE     Size[10];                          // File member size - decimal.
    BYTE     EndHeader[2];                      // String to end header.
} IMAGE_ARCHIVE_MEMBER_HEADER, *PIMAGE_ARCHIVE_MEMBER_HEADER;

#define ARCHIVE_MEMBER_HDR_SIZE 60
/*
 * Export Format
 */
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

/*
 * Import Format
 */
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    BYTE    Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

#include "../win_hdrs/pshpack8.h"                       // Use align 8 for the 64-bit IAT.

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;    // PBYTE
        ULONGLONG Function;        // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    //PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;

#include "../win_hdrs/poppack.h"                        // Back to 4 byte packing

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;    // PBYTE
        DWORD Function;        // PDWORD
        DWORD Ordinal;
        DWORD AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;
#endif

#define ORDINAL_FLAG64 0x8000000000000000ULL
#define ORDINAL_FLAG32 0x80000000
#define ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & ORDINAL_FLAG64) != 0)
#define SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & ORDINAL_FLAG32) != 0)

#ifndef USE_WINNT
/*
 * Thread Local Storage
 * (reference)
*/

#ifndef _WINDOWS
#define __stdcall
#endif

typedef void ( __stdcall *TLS_CALLBACK) ( // PIMAGE_TLS_CALLBACK *
    void* DllHandle,
    DWORD Reason,
    void* Reserved
    );

typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;        // PDWORD
    ULONGLONG AddressOfCallBacks;    // PIMAGE_TLS_CALLBACK *
    DWORD   SizeOfZeroFill;
    DWORD   Characteristics;
} IMAGE_TLS_DIRECTORY64;
typedef IMAGE_TLS_DIRECTORY64 * PIMAGE_TLS_DIRECTORY64;

typedef struct _IMAGE_TLS_DIRECTORY32 {
    DWORD   StartAddressOfRawData;
    DWORD   EndAddressOfRawData;
    DWORD   AddressOfIndex;
    DWORD   AddressOfCallBacks;    // PIMAGE_TLS_CALLBACK *
    DWORD   SizeOfZeroFill;
    DWORD   Characteristics;
} IMAGE_TLS_DIRECTORY32;
typedef IMAGE_TLS_DIRECTORY32 * PIMAGE_TLS_DIRECTORY32;


typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    DWORD   TimeDateStamp;            // 0 if not bound,
                        // -1 if bound, and real date\time stamp
                        //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                        // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

/*
 * New format import descriptors pointed to by DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ]
 */
typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    NumberOfModuleForwarderRefs;
    // Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BOUND_FORWARDER_REF {
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    Reserved;
} IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;


/*
 * Stub structure for IA64 transition stubs
 */
#define MIX_ISA_LIMIT    2

typedef struct _IMAGE_STUB_DIRECTORY {
    DWORD   SecondaryImportAddressTable;           // RVA of Secondary IAT
    WORD    ExpectedISA[MIX_ISA_LIMIT];      // Indicator of available ISA stubs
    DWORD   StubAddressTable[MIX_ISA_LIMIT]; // RVA of Stub Address Tables
} IMAGE_STUB_DIRECTORY, *PIMAGE_STUB_DIRECTORY;

#define M_IA64_STUB_NOT_AVAILABLE     ((PVOID) -1)
#define M_IA64_JMPE_MASK              0x00ffffff
#define M_IA64_JMPE_MARKER            0x0035000f

/*
 * Resource Format.
 *
 * Resource directory consists of two counts, following by a variable length
 * array of directory entries.  The first count is the number of entries at
 * beginning of the array that have actual names associated with each entry.
 * The entries are in ascending order, case insensitive strings.  The second
 * count is the number of entries that immediately follow the named entries.
 * This second count identifies the number of entries that have 16-bit integer
 * Ids as their name.  These entries are also sorted in ascending order.
 *
 * This structure allows fast lookup by either name or number, but for any
 * given resource entry only one form of lookup is supported, not both.
 * This is consistant with the syntax of the .RC file and the .RES file.
 */

typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    WORD    NumberOfNamedEntries;
    WORD    NumberOfIdEntries;
    //  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

#define RESOURCE_NAME_IS_STRING        0x80000000
#define RESOURCE_DATA_IS_DIRECTORY     0x80000000
#endif
/*
 * Each directory contains the 32-bit Name of the entry and an offset,
 * relative to the beginning of the resource directory of the data associated
 * with this directory entry.  If the name of the entry is an actual text
 * string instead of an integer Id, then the high order bit of the name field
 * is set to one and the low order 31-bits are an offset, relative to the
 * beginning of the resource directory of the string, which is of type
 * IMAGE_RESOURCE_DIRECTORY_STRING.  Otherwise the high bit is clear and the
 * low-order 16-bits are the integer Id that identify this resource directory
 * entry. If the directory entry is yet another resource directory (i.e. a
 * subdirectory), then the high order bit of the offset field will be
 * set to indicate this.  Otherwise the high bit is clear and the offset
 * field points to a resource data entry.
 */
namespace pe {
    typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
        union {
            struct {
                DWORD NameOffset : 31;
                DWORD NameIsString : 1;
            } name;
            DWORD   Name;
            WORD    Id;
        };
        union {
            DWORD   OffsetToData;
            struct {
                DWORD   OffsetToDirectory : 31;
                DWORD   DataIsDirectory : 1;
            } dir;
        };
    } IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;
};

#ifndef USE_WINNT
/*
 * For resource directory entries that have actual string names, the Name
 * field of the directory entry points to an object of the following type.
 * All of these string objects are stored together after the last resource
 * directory entry and before the first resource data object.  This minimizes
 * the impact of these variable length objects on the alignment of the fixed
 * size directory entry objects.
 */

typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
    WORD    Length;
    CHAR    NameString[1];
} IMAGE_RESOURCE_DIRECTORY_STRING, *PIMAGE_RESOURCE_DIRECTORY_STRING;


typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
    WORD    Length;
    WCHAR   NameString[1];
} IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;


/*
 * Each resource data entry describes a leaf node in the resource directory
 * tree.  It contains an offset, relative to the beginning of the resource
 * directory of the data for the resource, a size field that gives the number
 * of bytes of data at that offset, a CodePage that should be used when
 * decoding code point values within the resource data.  Typically for new
 * applications the code page would be the unicode code page.
 */

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    DWORD   OffsetToData;
    DWORD   Size;
    DWORD   CodePage;
    DWORD   Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

/*
 * Load Configuration Directory Entry
 */
typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY32 {
    DWORD   Size;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   GlobalFlagsClear;
    DWORD   GlobalFlagsSet;
    DWORD   CriticalSectionDefaultTimeout;
    DWORD   DeCommitFreeBlockThreshold;
    DWORD   DeCommitTotalFreeThreshold;
    DWORD   LockPrefixTable;            // VA
    DWORD   MaximumAllocationSize;
    DWORD   VirtualMemoryThreshold;
    DWORD   ProcessHeapFlags;
    DWORD   ProcessAffinityMask;
    WORD    CSDVersion;
    WORD    Reserved1;
    DWORD   EditList;                   // VA
    DWORD   SecurityCookie;             // VA
    DWORD   SEHandlerTable;             // VA
    DWORD   SEHandlerCount;
    //if Size > sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32)
    // IMAGE_LOAD_CONFIG_D32_W81 ldc_W81_part;
} IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY64{
    DWORD      Size;
    DWORD      TimeDateStamp;
    WORD       MajorVersion;
    WORD       MinorVersion;
    DWORD      GlobalFlagsClear;
    DWORD      GlobalFlagsSet;
    DWORD      CriticalSectionDefaultTimeout;
    ULONGLONG  DeCommitFreeBlockThreshold;
    ULONGLONG  DeCommitTotalFreeThreshold;
    ULONGLONG  LockPrefixTable;         // VA
    ULONGLONG  MaximumAllocationSize;
    ULONGLONG  VirtualMemoryThreshold;
    ULONGLONG  ProcessAffinityMask;
    DWORD      ProcessHeapFlags;
    WORD       CSDVersion;
    WORD       Reserved1;
    ULONGLONG  EditList;                // VA
    ULONGLONG  SecurityCookie;          // VA
    ULONGLONG  SEHandlerTable;          // VA
    ULONGLONG  SEHandlerCount;
    // if Size > sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)
    // IMAGE_LOAD_CONFIG_D64_W81 ldc_W81_part;
} IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;
#endif

// IMAGE_LOAD_CONFIG_DIRECTORY32 extension for W8.1 :
typedef struct _IMAGE_LOAD_CONFIG_D32_W81 {
    DWORD   GuardCFCheckFunctionPointer; //VA
    DWORD   Reserved2;
    DWORD   GuardCFFunctionTable; //VA
    DWORD   GuardCFFunctionCount;
    DWORD   GuardFlags;
} IMAGE_LOAD_CONFIG_D32_W81, *PIMAGE_LOAD_CONFIG_D32_W81;

// IMAGE_LOAD_CONFIG_DIRECTORY64 extension for W8.1 :
typedef struct _IMAGE_LOAD_CONFIG_D64_W81 {
    ULONGLONG   GuardCFCheckFunctionPointer; //VA
    ULONGLONG   Reserved2;
    ULONGLONG   GuardCFFunctionTable; //VA
    ULONGLONG   GuardCFFunctionCount;
    DWORD       GuardFlags;
} IMAGE_LOAD_CONFIG_D64_W81, *PIMAGE_LOAD_CONFIG_D64_W81;

#ifndef USE_WINNT
/*
 * WIN CE Exception table format
 *
 * Function table entry format.  Function table is pointed to by the
 * IMAGE_DIRECTORY_ENTRY_EXCEPTION directory entry.
 */
typedef struct _IMAGE_CE_RUNTIME_FUNCTION_ENTRY {
    DWORD FuncStart;
    DWORD PrologLen : 8;
    DWORD FuncLen : 22;
    DWORD ThirtyTwoBit : 1;
    DWORD ExceptionFlag : 1;
} IMAGE_CE_RUNTIME_FUNCTION_ENTRY, * PIMAGE_CE_RUNTIME_FUNCTION_ENTRY;

/*
 * Function table entry format for IA64 images.  Function table is
 * pointed to by the IMAGE_DIRECTORY_ENTRY_EXCEPTION directory entry.
 * This definition duplicates the one in ntia64.h for use by portable
 * image file mungers.
 */

typedef struct _IMAGE_IA64_RUNTIME_FUNCTION_ENTRY {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindInfoAddress;
} IMAGE_IA64_RUNTIME_FUNCTION_ENTRY, *PIMAGE_IA64_RUNTIME_FUNCTION_ENTRY;

/*
 * Function table entry format for ALPHA images.  Function table is
 * pointed to by the IMAGE_DIRECTORY_ENTRY_EXCEPTION directory entry.
 * This definition duplicates ones in ntmips.h and ntalpha.h for use
 * by portable image file mungers.
 */

typedef struct _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD ExceptionHandler;
    DWORD HandlerData;
    DWORD PrologEndAddress;
} IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY;

typedef struct _IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY {
    ULONGLONG BeginAddress;
    ULONGLONG EndAddress;
    ULONGLONG ExceptionHandler;
    ULONGLONG HandlerData;
    ULONGLONG PrologEndAddress;
} IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY;

typedef  IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY  IMAGE_AXP64_RUNTIME_FUNCTION_ENTRY;
typedef PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY PIMAGE_AXP64_RUNTIME_FUNCTION_ENTRY;

/*
 * Debug Format
 */

typedef struct _IMAGE_DEBUG_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Type;
    DWORD   SizeOfData;
    DWORD   AddressOfRawData;
    DWORD   PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;


typedef struct _IMAGE_COFF_SYMBOLS_HEADER {
    DWORD   NumberOfSymbols;
    DWORD   LvaToFirstSymbol;
    DWORD   NumberOfLinenumbers;
    DWORD   LvaToFirstLinenumber;
    DWORD   RvaToFirstByteOfCode;
    DWORD   RvaToLastByteOfCode;
    DWORD   RvaToFirstByteOfData;
    DWORD   RvaToLastByteOfData;
} IMAGE_COFF_SYMBOLS_HEADER, *PIMAGE_COFF_SYMBOLS_HEADER;

enum frame {
    FPO = 0,
    TRAP = 1,
    TSS = 2,
    NONFPO = 3
};


typedef struct _FPO_DATA {
    DWORD       ulOffStart;             // offset 1st byte of function code
    DWORD       cbProcSize;             // # bytes in function
    DWORD       cdwLocals;              // # bytes in locals/4
    WORD        cdwParams;              // # bytes in params/4
    WORD        cbProlog : 8;           // # bytes in prolog
    WORD        cbRegs   : 3;           // # regs saved
    WORD        fHasSEH  : 1;           // TRUE if SEH in func
    WORD        fUseBP   : 1;           // TRUE if EBP has been allocated
    WORD        reserved : 1;           // reserved for future use
    WORD        cbFrame  : 2;           // frame type
} FPO_DATA, *PFPO_DATA;
#define SIZEOF_RFPO_DATA 16


#define DEBUG_MISC_EXENAME    1

typedef struct _IMAGE_DEBUG_MISC {
    DWORD       DataType;               // type of misc data, see defines
    DWORD       Length;                 // total length of record, rounded to four byte multiple.
    BOOLEAN     Unicode;                // TRUE if data is unicode string
    BYTE        Reserved[3];
    BYTE        Data[1];              // Actual data
} IMAGE_DEBUG_MISC, *PIMAGE_DEBUG_MISC;


/*
 * Function table extracted from MIPS/ALPHA/IA64 images.  Does not contain
 * information needed only for runtime support.  Just those fields for
 * each entry needed by a debugger.
 */

typedef struct _IMAGE_FUNCTION_ENTRY {
    DWORD   StartingAddress;
    DWORD   EndingAddress;
    DWORD   EndOfPrologue;
} IMAGE_FUNCTION_ENTRY, *PIMAGE_FUNCTION_ENTRY;

typedef struct _IMAGE_FUNCTION_ENTRY64 {
    ULONGLONG   StartingAddress;
    ULONGLONG   EndingAddress;
    union {
        ULONGLONG EndOfPrologue;
        ULONGLONG UnwindInfoAddress;
    };
} IMAGE_FUNCTION_ENTRY64, *PIMAGE_FUNCTION_ENTRY64;

/*
 * Debugging information can be stripped from an image file and placed
 * in a separate .DBG file, whose file name part is the same as the
 * image file name part (e.g. symbols for CMD.EXE could be stripped
 * and placed in CMD.DBG).  This is indicated by the IMAGE_FILE_DEBUG_STRIPPED
 * flag in the Characteristics field of the file header.  The beginning of
 * the .DBG file contains the following structure which captures certain
 * information from the image file.  This allows a debug to proceed even if
 * the original image file is not accessable.  This header is followed by
 * zero of more IMAGE_SECTION_HEADER structures, followed by zero or more
 * IMAGE_DEBUG_DIRECTORY structures.  The latter structures and those in
 * the image file contain file offsets relative to the beginning of the
 * .DBG file.
 *
 * If symbols have been stripped from an image, the IMAGE_DEBUG_MISC structure
 * is left in the image file, but not mapped.  This allows a debugger to
 * compute the name of the .DBG file, from the name of the image in the
 * IMAGE_DEBUG_MISC structure.
 */

typedef struct _IMAGE_SEPARATE_DEBUG_HEADER {
    WORD        Signature;
    WORD        Flags;
    WORD        Machine;
    WORD        Characteristics;
    DWORD       TimeDateStamp;
    DWORD       CheckSum;
    DWORD       ImageBase;
    DWORD       SizeOfImage;
    DWORD       NumberOfSections;
    DWORD       ExportedNamesSize;
    DWORD       DebugDirectorySize;
    DWORD       SectionAlignment;
    DWORD       Reserved[2];
} IMAGE_SEPARATE_DEBUG_HEADER, *PIMAGE_SEPARATE_DEBUG_HEADER;

typedef struct _NON_PAGED_DEBUG_INFO {
    WORD        Signature;
    WORD        Flags;
    DWORD       Size;
    WORD        Machine;
    WORD        Characteristics;
    DWORD       TimeDateStamp;
    DWORD       CheckSum;
    DWORD       SizeOfImage;
    ULONGLONG   ImageBase;
    //DebugDirectorySize
    //IMAGE_DEBUG_DIRECTORY
} NON_PAGED_DEBUG_INFO, *PNON_PAGED_DEBUG_INFO;

enum dbg_signature {
    SEPARATE = 0x4944,
    NON_PAGED = 0x494E
};

#define SEPARATE_DEBUG_FLAGS_MASK 0x8000
#define SEPARATE_DEBUG_MISMATCH 0x8000  // when DBG was updated, the old checksum didn't match.

/*
 *  The .arch section is made up of headers, each describing an amask position/value
 *  pointing to an array of IMAGE_ARCHITECTURE_ENTRY's.  Each "array" (both the header
 *  and entry arrays) are terminiated by a quadword of 0xffffffffL.
 *
 *  NOTE: There may be quadwords of 0 sprinkled around and must be skipped.
 */

typedef struct _ImageArchitectureHeader {
    unsigned int AmaskValue: 1;                 // 1 -> code section depends on mask bit
                            // 0 -> new instruction depends on mask bit
    int :7;                                     // MBZ
    unsigned int AmaskShift: 8;                 // Amask bit in question for this fixup
    int :16;                                    // MBZ
    DWORD FirstEntryRVA;                        // RVA into .arch section to array of ARCHITECTURE_ENTRY's
} IMAGE_ARCHITECTURE_HEADER, *PIMAGE_ARCHITECTURE_HEADER;

typedef struct _ImageArchitectureEntry {
    DWORD FixupInstRVA;                         // RVA of instruction to fixup
    DWORD NewInst;                              // fixup instruction (see alphaops.h)
} IMAGE_ARCHITECTURE_ENTRY, *PIMAGE_ARCHITECTURE_ENTRY;

#include "../win_hdrs/poppack.h"                // Back to the initial value

/*
 * The following structure defines the new import object.  Note the values of the first two fields,
 * which must be set as stated in order to differentiate old and new import members.
 * Following this structure, the linker emits two null-terminated strings used to recreate the
 * import at the time of use.  The first string is the import's name, the second is the dll's name.
 */
#define IMPORT_OBJECT_HEADER_SIG2  0xffff

typedef struct IMPORT_OBJECT_HEADER {
    WORD    Sig1;                       // Must be IMAGE_FILE_MACHINE_UNKNOWN
    WORD    Sig2;                       // Must be IMPORT_OBJECT_HEADER_SIG2.
    WORD    Version;
    WORD    Machine;
    DWORD   TimeDateStamp;              // Time/date stamp
    DWORD   SizeOfData;                 // particularly useful for incremental links

    union {
        WORD    Ordinal;                // if grf & IMPORT_OBJECT_ORDINAL
        WORD    Hint;
    };

    WORD    Type : 2;                   // IMPORT_TYPE
    WORD    NameType : 3;               // IMPORT_NAME_TYPE
    WORD    Reserved : 11;              // Reserved. Must be zero.
} IMPORT_OBJECT_HEADER;

typedef enum IMPORT_OBJECT_TYPE
{
    IMPORT_OBJECT_CODE = 0,
    IMPORT_OBJECT_DATA = 1,
    IMPORT_OBJECT_CONST = 2,
} IMPORT_OBJECT_TYPE;

typedef enum IMPORT_OBJECT_NAME_TYPE
{
    IMPORT_OBJECT_ORDINAL = 0,          // Import by ordinal
    IMPORT_OBJECT_NAME = 1,             // Import name == public symbol name.
    IMPORT_OBJECT_NAME_NO_PREFIX = 2,   // Import name == public symbol name skipping leading ?, @, or optionally _.
    IMPORT_OBJECT_NAME_UNDECORATE = 3,  // Import name == public symbol name skipping leading ?, @, or optionally _
                        // and truncating at first @
} IMPORT_OBJECT_NAME_TYPE;

/*
 * End Image Format
 */

/* additional PE structures  - from other headers */

#include "../win_hdrs/pshpack4.h"                   // 4 byte packing (DWORD alligned)
#endif

typedef struct _WIN_CERTIFICATE {
    DWORD dwLength;
    WORD wRevision;
    WORD wCertificateType; // of CERTIFICATE_TYPE
    BYTE bCertificate[1];
} WIN_CERTIFICATE, *LPWIN_CERTIFICATE;

typedef enum _CERTIFICATE_TYPE {
    WIN_CERT_TYPE_X509  = 0x0001,     //bCertificate contains an X.509 certificate.
    WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002,     //bCertificate contains a PKCS SignedData structure.
    WIN_CERT_TYPE_RESERVED_1 = 0x0003,     //Reserved.
    WIN_CERT_TYPE_PKCS1_SIGN = 0x0009    //bCertificate contains PKCS1_MODULE_SIGN fields.
} CERTIFICATE_TYPE;


//DELAY_LOAD

typedef struct _IMAGE_DELAY_LOAD32 {
    DWORD grAttrs;        //must be 0
    DWORD szName;        //RVA
    DWORD phmod;        //RVA
    DWORD pIAT;            //RVA
    DWORD pINT;            //RVA
    DWORD pBoundIAT;    //RVA
    DWORD pUnloadIAT;    //RVA
    DWORD dwTimestamp;
} IMAGE_DELAY_LOAD32, *LPIMAGE_DELAY_LOAD32;

typedef struct _IMAGE_DELAY_LOAD64 {
    ULONGLONG grAttrs;        //must be 0
    ULONGLONG szName;        //RVA
    ULONGLONG phmod;        //RVA
    ULONGLONG pIAT;            //RVA
    ULONGLONG pINT;            //RVA
    ULONGLONG pBoundIAT;    //RVA
    ULONGLONG pUnloadIAT;    //RVA
    ULONGLONG dwTimestamp;
} IMAGE_DELAY_LOAD64, *LPIMAGE_DELAY_LOAD64;

#ifndef USE_WINNT
// DIR_EXCEPTION -> RUNTIME_FUNCTION -> UNWIND_INFO

typedef struct _UNWIND_CODE {
    BYTE Offset;
    BYTE UnwindOperationCode : 4;
    BYTE OperationInfo : 4;
} UNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCodes[1]; /* UNWIND_CODEs, real size =  CountOfCodes */
/* here comes:
    _IMAGE_IA64_RUNTIME_FUNCTION_ENTRY
or
    _UNWIND_INFO_EXCEPTHNDL

If flag UNW_FLAG_CHAININFO is set then the UNWIND_INFO structure ends with three UWORDs.
These UWORDs represent the RUNTIME_FUNCTION information for the function of the chained unwind.
*/
} UNWIND_INFO, *PUNWIND_INFO;

typedef struct _UNWIND_INFO_EXCEPTHNDL {
/*
ExceptionHandlerAddress:
    This is an image-relative pointer to either the function's language-specific exception/termination handler
    (if flag UNW_FLAG_CHAININFO is clear and one of the flags UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER is set).
*/
    LONG ExceptionHandlerAddress; //RVA
    BYTE LanguageSpecificData;    //Language-specific handler data (optional)
} UNWIND_INFO_FUNC, LPUNWIND_INFO_FUNC;

#include "../win_hdrs/poppack.h"                // Back to the initial value

#include "../win_hdrs/pshpack2.h"                   // 2 byte packing (WORD alligned)
#endif

// IMAGE_BASE_RELOCATION -> Entry:
typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type: 4;
} BASE_RELOCATION_ENTRY;

#ifndef USE_WINNT
//From winuser.h:
#define DIFFERENCE 11

#define CREATEPROCESS_MANIFEST_RESOURCE_ID 1
#define ISOLATIONAWARE_MANIFEST_RESOURCE_ID 2
#define ISOLATIONAWARE_NOSTATICIMPORT_MANIFEST_RESOURCE_ID 3

//#include "../win_hdrs/poppack.h"                // Back to the initial value
//#include "../win_hdrs/pshpack4.h"                   // 4 byte packing (DWORD alligned)

typedef struct tagVS_FIXEDFILEINFO
{
    DWORD   dwSignature;            /* e.g. 0xfeef04bd */
    DWORD   dwStrucVersion;         /* e.g. 0x00000042 = "0.42" */
    DWORD   dwFileVersionMS;        /* e.g. 0x00030075 = "3.75" */
    DWORD   dwFileVersionLS;        /* e.g. 0x00000031 = "0.31" */
    DWORD   dwProductVersionMS;     /* e.g. 0x00030010 = "3.10" */
    DWORD   dwProductVersionLS;     /* e.g. 0x00000031 = "0.31" */
    DWORD   dwFileFlagsMask;        /* = 0x3F for version "0.42" */
    DWORD   dwFileFlags;            /* e.g. VFF_DEBUG | VFF_PRERELEASE */
    DWORD   dwFileOS;               /* e.g. VOS_DOS_WINDOWS16 */
    DWORD   dwFileType;             /* e.g. VFT_DRIVER */
    DWORD   dwFileSubtype;          /* e.g. VFT2_DRV_KEYBOARD */
    DWORD   dwFileDateMS;           /* e.g. 0 */
    DWORD   dwFileDateLS;           /* e.g. 0 */
} VS_FIXEDFILEINFO;

//#include "../win_hdrs/poppack.h"                // Back to the initial value
//#include "../win_hdrs/pshpack2.h"                   // 2 byte packing (WORD alligned)


typedef struct {
    WORD  wLength;
    WORD  wValueLength;
    WORD  wType;
    WCHAR szKey;
    WORD  Padding;
    WORD  Value;
} String;

typedef struct {
    WORD   wLength;
    WORD   wValueLength;
    WORD   wType;
    WCHAR  szKey;
    WORD   Padding;
    String Children;
} StringTable;
/*
typedef struct {
    WORD        wLength;
    WORD        wValueLength;
    WORD        wType;
    WCHAR       szKey;
    WORD        Padding;
    StringTable Children;
} StringFileInfo;
*/
typedef struct {
    WORD  wLength;
    WORD  wValueLength;
    WORD  wType;
    WCHAR szKey;
    WORD  Padding;
    DWORD Value;
} Var;
/*
typedef struct {
    WORD  wLength;
    WORD  wValueLength;
    WORD  wType;
    WCHAR szKey;
    WORD  Padding;
    Var   Children;
} VarFileInfo;
*/

#include "../win_hdrs/poppack.h"                // Back to the initial value


#endif //USE_WINNT

namespace pe {

    enum opt_hdr_magic {
        OH_NT32 = 0x10b,
        OH_NT64 = 0x20b,
        OH_ROM = 0x107
    };

    enum resource_type {
        RESTYPE_CURSOR = 1,
        RESTYPE_FONT = 8,
        RESTYPE_BITMAP = 2,
        RESTYPE_ICON = 3,
        RESTYPE_MENU = 4,
        RESTYPE_DIALOG = 5,
        RESTYPE_STRING = 6,
        RESTYPE_FONTDIR = 7,
        RESTYPE_ACCELERATOR = 9,
        RESTYPE_RCDATA = 10,
        RESTYPE_MESSAGETABLE = 11,

        RESTYPE_GROUP_CURSOR = (DWORD)RESTYPE_CURSOR + DIFFERENCE,
        RESTYPE_GROUP_ICON = (DWORD)RESTYPE_ICON + DIFFERENCE,
        RESTYPE_VERSION = 16,
        RESTYPE_DLGINCLUDE = 17,
        RESTYPE_PLUGPLAY = 19,
        RESTYPE_VXD = 20,
        RESTYPE_ANICURSOR = 21,
        RESTYPE_ANIICON = 22,
        RESTYPE_HTML = 23,
        RESTYPE_MANIFEST = 24,
    };

    enum dir_entry {
        DIR_EXPORT = 0,   // Export Directory
        DIR_IMPORT = 1,   // Import Directory
        DIR_RESOURCE = 2,   // Resource Directory
        DIR_EXCEPTION = 3,   // Exception Directory
        DIR_SECURITY = 4,   // Security Directory
        DIR_BASERELOC = 5,   // Base Relocation Table
        DIR_DEBUG = 6,   // Debug Directory//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7,   // (X86 usage)
        DIR_ARCHITECTURE = 7,   // Architecture Specific Data
        DIR_GLOBALPTR = 8,   // RVA of GP
        DIR_TLS = 9,   // TLS Directory
        DIR_LOAD_CONFIG = 10,   // Load Configuration Directory
        DIR_BOUND_IMPORT = 11,   // Bound Import Directory in headers
        DIR_IAT = 12,   // Import Address Table
        DIR_DELAY_IMPORT = 13,   // Delay Load Import Descriptors
        DIR_COM_DESCRIPTOR = 14,   // COM Runtime descriptor
        DIR_ENTRIES_COUNT // counter - convinience field
    };

    enum signature {
        S_LX = 0x584C,
        S_W3_WIN386 = 0x3357,
        S_W4_VMM32 = 0x3457,
        S_OS2 = 0x454E,
        S_VXD = 0x454C,
        S_NT = 0x00004550,
        S_OS2_LE = S_VXD,
        S_DOS = 0x5A4D, // MZ
        S_DOS2 = 0x4D5A //ZM
    };

    enum debug_type
    {
        DT_UNKNOWN = 0,
        DT_COFF = 1,
        DT_CODEVIEW = 2,
        DT_FPO = 3,
        DT_MISC = 4,
        DT_EXCEPTION = 5,
        DT_FIXUP = 6,
        DT_OMAP_TO_SRC = 7,
        DT_OMAP_FROM_SRC = 8,
        DT_BORLAND = 9,
        DT_RESERVED10 = 10,
        DT_CLSID = 11
    };

    enum subsystem {
        SUB_UNKNOWN = 0,   // Unknown subsystem.
        SUB_NATIVE = 1,   // Image doesn't require a subsystem.
        SUB_WINDOWS_GUI = 2,   // Image runs in the Windows GUI subsystem.
        SUB_WINDOWS_CUI = 3,   // Image runs in the Windows character subsystem.
        SUB_OS2_CUI = 5,   // image runs in the OS/2 character subsystem.
        SUB_POSIX_CUI = 7,   // image runs in the Posix character subsystem.
        SUB_NATIVE_WINDOWS = 8,   // image is a native Win9x driver.
        SUB_WINDOWS_CE_GUI = 9,   // Image runs in the Windows CE subsystem.
        SUB_EFI_APPLICATION = 10,  //
        SUB_EFI_BOOT_SERVICE_DRIVER = 11,   //
        SUB_EFI_RUNTIME_DRIVER = 12,  //
        SUB_EFI_ROM = 13,
        SUB_XBOX = 14,
        SUB_WINDOWS_BOOT_APP = 16
    };

    /*
    * DllCharacteristics Entries
    */
    enum dll_charact {
        // DLL_PROCESS_INIT           0x0001     // Reserved.
        // DLL_PROCESS_TERM           0x0002     // Reserved.
        // DLL_THREAD_INIT            0x0004     // Reserved.
        // DLL_THREAD_TERM            0x0008     // Reserved.
        DLL_DYNAMIC_BASE = 0x0040,     // DLL can move.
        DLL_FORCE_INTEGRITY = 0x0080,     // Code Integrity Image
        DLL_NX_COMPAT = 0x0100,     // Image is NX compatible
        DLL_NO_ISOLATION = 0x0200,     // Image understands isolation and doesn't want it
        DLL_NO_SEH = 0x0400,     // Image does not use SEH.  No SE handler may reside in this image
        DLL_NO_BIND = 0x0800,     // Do not bind this image.
        DLL_APPCONTAINER = 0x1000, // AppContainer (W8)
        DLL_WDM_DRIVER = 0x2000,     // Driver uses WDM model
        DLL_GUARD_CF = 0x4000, // Guard CF (W8.1)
        DLL_TERMINAL_SERVER_AWARE = 0x8000
    };

    #define INFOTEXT_LEN 17

    typedef struct version_info {
        WORD  length;
        WORD valueLength;
        WORD type; //0 -bin, 1-text
        WORD key[INFOTEXT_LEN];
        VS_FIXEDFILEINFO Value;
        WORD children; //VS_VERSIONCHILD in array
    } VS_VERSIONINFO;

    typedef struct version_child {
        WORD  wLength;
        WORD  wValueLength;
        WORD  wType;
        WCHAR szKey[INFOTEXT_LEN];
        WORD subVal; // String or Var, depending on wType
    } VS_VERSIONCHILD;
}
