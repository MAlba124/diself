#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define EXTRACT_32_BITS(__addr, __offset) \
  __addr[__offset] \
  + (__addr[__offset + 1] << 8) \
  + (__addr[__offset + 2] << 16) \
  + (__addr[__offset + 3] << 24)

#define EXTRACT_64_BITS(__addr, __offset) \
  __addr[__offset] \
  + (__addr[__offset + 1] << 8) \
  + (__addr[__offset + 2] << 16) \
  + (__addr[__offset + 3] << 24) \
  + ((int64_t)__addr[__offset + 4] << 32) \
  + ((int64_t)__addr[__offset + 5] << 40) \
  + ((int64_t)__addr[__offset + 6] << 48) \
  + ((int64_t)__addr[__offset + 7] << 56)

typedef uint8_t u8;

enum BitFormat {
  BIT32 = 1,
  BIT64 = 2
};

enum Endianness {
  LITTLE = 1,
  BIG    = 2
};

enum TargetABI {
  SYSTEM_V                     = 0x00,
  HP_UX                        = 0x01,
  NETBSD                       = 0x02,
  LINUX                        = 0x03,
  GNU_HURD                     = 0x04,
  SOLARIS                      = 0x06,
  AIX                          = 0x07,
  IRIX                         = 0x08,
  FREEBSD                      = 0x09,
  TRU64                        = 0x0A,
  NOVELL_MODESTO               = 0x0B,
  OPENBSD                      = 0x0C,
  OPENVMS                      = 0x0D,
  NONSTOP_KERNEL               = 0x0E,
  AROS                         = 0x0F,
  FENIXOS                      = 0x10,
  NUXI_CLOUDABI                = 0x11,
  STRATUS_TECHNOLOGIES_OPENVOS = 0x12
};

enum ELFType {
  NONE   = 0x0000,
  REL    = 0x0001,
  EXEC   = 0x0002,
  DYN    = 0x0003,
  CORE   = 0x0004,
  LOOS   = 0xFE00,
  HIOS   = 0xFEFF,
  LOPROC = 0xFF00,
  HIPROC = 0xFFFF
};

static bool
elf_type_is_valid(uint16_t t) {
  return t == NONE || t == REL || t == EXEC || t == DYN || t == CORE
  || t == LOOS || t == HIOS || t == LOPROC || t == HIPROC;
}

enum ISA {
  NO                                 = 0x000,
  ATT_WE_32100                       = 0x001,
  SPARC                              = 0x002,
  X86                                = 0x003,
  MOTOROLA_MK68K                     = 0x004,
  MOTOROLA_MK88K                     = 0x005,
  INTEL_MCU                          = 0x006,
  INTEL_80860                        = 0x007,
  MIPS                               = 0x008,
  IBM_SYSTEM_370                     = 0x009,
  MIPBS_RS3000_LE                    = 0x00A,
  HP_PA_RISC                         = 0x00F,
  INTEL_80960                        = 0x013,
  POWER_PC                           = 0x014,
  POWER_PC_64                        = 0x015,
  S390                               = 0x016,
  IBM_SPU_SPC                        = 0x017,
  NEC_V800                           = 0x024,
  FUJITSU_FR20                       = 0x025,
  TRW_RH_32                          = 0x026,
  MOTOROLA_RCE                       = 0x027,
  ARM                                = 0x028,
  DIGITAL_ALPHA                      = 0x029,
  SUPER_H                            = 0x02A,
  SPARC_V_9                          = 0x02B,
  SIEMENS_TRICORE_EMBEDDED_PROCESSOR = 0x02C,
  ARGONAUT_RISC_CORE                 = 0x02D,
  HITACHI_H8_300                     = 0x02E,
  HITACHI_H8_300H                    = 0x02F,
  HITACHI_H8S                        = 0x030,
  HITACHI_H8_500                     = 0x031,
  IA_64                              = 0x032,
  STANFORD_MIPS_X                    = 0x033,
  MOTOROLA_COLD_FIRE                 = 0x034,
  MOTOROLA_M68HC12                   = 0x035,
  FUJITSU_MMA                        = 0x036,
  SIEMENS_PCP                        = 0x037,
  SONY_NCPU_EMBEDDED_RISC_PROCESSOR  = 0x038,
  DENSO_NDR1                         = 0x039,
  MOTOROLA_STAR_CORE                 = 0x03A,
  TOYOTA_ME16                        = 0x03B,
  STMICROELECTRONICS_ST100           = 0x03C,
  ADVANDE_LOGIC_CORP_TINYJ           = 0x03D,
  AMD_X86_64                         = 0x03E,
  SONY_DSP                           = 0x03F,
  DIGITAL_EQUIPMENT_CORP_PDP_10      = 0x040,
  DIGITAL_EQUIPMENT_CORP_PDP_11      = 0x041,
  SIEMENS_FX66                       = 0x042,
  STMICROELECTRONICS_ST9             = 0x043,
  STMICROELECTRONICS_ST7             = 0x044,
  MOTOROLA_MC68HC16                  = 0x045,
  MOTOROLA_MC68HC11                  = 0x046,
  MOTOROLA_MC68HC08                  = 0x047,
  MOTOROLA_MC68HC05                  = 0x048,
  SILICON_GRAPHICS_SVX               = 0x049,
  STMICROELECTRONICS_ST19            = 0x04A,
  DIGITAL_VAX                        = 0x04B,
  AXIS_COMS_32                       = 0x04C,
  INFINEON_TECHS_32                  = 0x04D,
  ELEMENT_14_DSP                     = 0x04E,
  LSI_LOGIC_DSP                      = 0x04F,
  TMS320C6000                        = 0x08C,
  MCST_ELBRUS_E2K                    = 0x0AF,
  ARM_64                             = 0x0B7,
  ZILOG_Z8                           = 0x0DC,
  RISC_V                             = 0x0F3,
  BERKELEY_PACKET_FILTER             = 0x0F7,
  WDC_65C816                         = 0x101,
  LOONG_ARCH                         = 0x102
};

static bool
isa_is_valid(uint16_t i) {
  return i == NO || i == ATT_WE_32100 || i == SPARC || i == X86 || i == MOTOROLA_MK68K || i == MOTOROLA_MK88K
  || i == INTEL_MCU || i == INTEL_80860 || i == MIPS || i == IBM_SYSTEM_370 || i == MIPBS_RS3000_LE
  || i == HP_PA_RISC || i == INTEL_80960 || i == POWER_PC || i == POWER_PC_64 || i == S390
  || i == IBM_SPU_SPC || i == NEC_V800 || i == FUJITSU_FR20 || i == TRW_RH_32 || i == MOTOROLA_RCE
  || i == ARM || i == DIGITAL_ALPHA || i == SUPER_H || i == SPARC_V_9 || i == SIEMENS_TRICORE_EMBEDDED_PROCESSOR
  || i == ARGONAUT_RISC_CORE || i == HITACHI_H8_300 || i == HITACHI_H8_300H || i == HITACHI_H8S || i == HITACHI_H8_500
  || i == IA_64 || i == STANFORD_MIPS_X || i == MOTOROLA_COLD_FIRE || i == MOTOROLA_M68HC12 || i == FUJITSU_MMA
  || i == SIEMENS_PCP || i == SONY_NCPU_EMBEDDED_RISC_PROCESSOR || i == DENSO_NDR1 || i == MOTOROLA_STAR_CORE
  || i == TOYOTA_ME16 || i == STMICROELECTRONICS_ST100 || i == ADVANDE_LOGIC_CORP_TINYJ || i == AMD_X86_64
  || i == SONY_DSP || i == DIGITAL_EQUIPMENT_CORP_PDP_10 || i == DIGITAL_EQUIPMENT_CORP_PDP_11 || i == SIEMENS_FX66
  || i == STMICROELECTRONICS_ST9 || i == STMICROELECTRONICS_ST7 || i == MOTOROLA_MC68HC16 || i == MOTOROLA_MC68HC11
  || i == MOTOROLA_MC68HC08 || i == MOTOROLA_MC68HC05 || i == SILICON_GRAPHICS_SVX || i == STMICROELECTRONICS_ST19
  || i == DIGITAL_VAX || i == AXIS_COMS_32 || i == INFINEON_TECHS_32 || i == ELEMENT_14_DSP || i == LSI_LOGIC_DSP
  || i == TMS320C6000 || i == MCST_ELBRUS_E2K || i == ARM_64 || i == ZILOG_Z8 || i == RISC_V || i == BERKELEY_PACKET_FILTER
  || i == WDC_65C816 || i == LOONG_ARCH;
}

enum ProgramHeaderEntryType {
  PHT_NULL         = 0x00000000,
  PHT_LOAD         = 0x00000001,
  PHT_DYNAMIC      = 0x00000002,
  PHT_INTERP       = 0x00000003,
  PHT_NOTE         = 0x00000004,
  PHT_SHLIB        = 0x00000005,
  PHT_PHDR         = 0x00000006,
  PHT_TLS          = 0x00000007,
  PHT_LOOS         = 0x60000000,
  PHT_HIOS         = 0x6FFFFFFF,
  PHT_LOPROC       = 0x70000000,
  PHT_HIPROC       = 0x7FFFFFFF,
  PHT_GNU_PROPERTY = 0x6474E553,
  PHT_SUNW_FRAME   = 0x6474E550,
  PHT_GNU_STACK    = 0x6474E551,
  PHT_GNU_RELRO    = 0x6474E552
};

static bool
phe_type_is_valid(int32_t t) {
  return t == PHT_NULL || t == PHT_LOAD || t == PHT_DYNAMIC || t == PHT_INTERP || t == PHT_NOTE
  || t == PHT_SHLIB || t == PHT_PHDR || t == PHT_TLS || t == PHT_LOOS || t == PHT_HIOS
  || t == PHT_LOPROC || t == PHT_HIPROC || t == PHT_GNU_PROPERTY || t == PHT_SUNW_FRAME || t == PHT_GNU_STACK
  || t == PHT_GNU_RELRO;
}

struct ProgramHeaderEntry {
  enum ProgramHeaderEntryType type;
  int32_t flags;
  int64_t offset;
  int64_t virtual_addr;
  int64_t physical_addr;
  int64_t file_size;
  int64_t mem_size;
  int64_t align;
};

struct ProgramHeader {
  int64_t offset;
  int16_t size;
  int16_t entries;
  struct ProgramHeaderEntry *entries_ptr;
};

enum SectionHeaderEntryType {
  SHT_NULL          = 0x00000000,
  SHT_PROGBITS      = 0x00000001,
  SHT_SYMTAB        = 0x00000002,
  SHT_STRTAB        = 0x00000003,
  SHT_RELA          = 0x00000004,
  SHT_HASH          = 0x00000005,
  SHT_DYNAMIC       = 0x00000006,
  SHT_NOTE          = 0x00000007,
  SHT_NOBITS        = 0x00000008,
  SHT_REL           = 0x00000009,
  SHT_SHLIB         = 0x0000000A,
  SHT_DYNSYM        = 0x0000000B,
  SHT_INIT_ARRAY    = 0x0000000E,
  SHT_FINI_ARRAY    = 0x0000000F,
  SHT_PREINIT_ARRAY = 0x00000010,
  SHT_GROUP         = 0x00000011,
  SHT_SYMTAB_SHNDX  = 0x00000012,
  SHT_NUM           = 0x00000013,
  SHT_LOOS          = 0x60000000,
  SHT_GNU_HASH      = 0x6FFFFFF6,
  SHT_GNU_VERSYM    = 0x6FFFFFFF,
  SHT_GNU_VERNEED   = 0x6FFFFFFE
};

static bool
she_type_is_valid(int32_t t) {
  return t ==  SHT_NULL || t ==  SHT_PROGBITS || t ==  SHT_SYMTAB || t ==  SHT_STRTAB || t ==  SHT_RELA
  || t ==  SHT_HASH || t ==  SHT_DYNAMIC || t ==  SHT_NOTE || t ==  SHT_NOBITS || t ==  SHT_REL
  || t ==  SHT_SHLIB || t ==  SHT_DYNSYM || t ==  SHT_INIT_ARRAY || t ==  SHT_FINI_ARRAY || t ==  SHT_PREINIT_ARRAY
  || t ==  SHT_GROUP || t ==  SHT_SYMTAB_SHNDX || t ==  SHT_NUM || t ==  SHT_LOOS || t ==  SHT_GNU_HASH
  || t ==  SHT_GNU_VERSYM || t ==  SHT_GNU_VERNEED;
}

enum SectionHeaderEntryFlag {
  SHF_WRITE            = 0x1,
  SHF_ALLOC            = 0x2,
  SHF_EXECINSTR        = 0x4,
  SHF_MERGE            = 0x10,
  SHF_STRINGS          = 0x20,
  SHF_INFO_LINK        = 0x40,
  SHF_LINK_ORDER       = 0x80,
  SHF_OS_NONCONFORMING = 0x100,
  SHF_GROUP            = 0x200,
  SHF_TLS              = 0x400,
  SHF_MASKOS           = 0x0FF00000,
  SHF_MASKPROC         = 0xF0000000,
  SHF_ORDERED          = 0x4000000,
  SHF_EXCLUDE          = 0x8000000
};

struct SectionHeaderEntry {
  int32_t str_offset;
  enum SectionHeaderEntryType type;
  int64_t flags;
  int64_t addr;
  int64_t offset;
  int64_t size;
  int32_t link;
  int32_t info;
  int64_t addralign;
  int64_t entries_size;
};

struct SectionHeader {
  int64_t offset;
  int16_t size;
  int16_t entries;
  int16_t str_index;
  struct SectionHeaderEntry *entries_ptr;
};

struct ELF {
  enum BitFormat bf;
  enum Endianness end;
  bool is_og;
  enum TargetABI abi;
  enum ELFType type;
  enum ISA isa;
  int64_t entry;
  struct ProgramHeader ph;
  struct SectionHeader sh;
  int32_t flags;
};

static const char *
bit_format_as_string(enum BitFormat bf) {
  switch (bf) {
  case BIT32: return "32 bit";
  case BIT64: return "64 bit";
  default: return    "n/a";
  }
}

static const char *
endianness_as_string(enum Endianness e) {
  switch (e) {
  case LITTLE: return "LE (little-endian)";
  case BIG: return    "BE (big-endian)";
  default: return     "n/a";
  }
}

static const char *
target_abi_as_string(enum TargetABI abi) {
  switch (abi) {
  case SYSTEM_V: return                     "System V";
  case HP_UX: return                        "HP-UX";
  case NETBSD: return                       "NetBSD";
  case LINUX: return                        "Linux";
  case GNU_HURD: return                     "GNU Hurd";
  case SOLARIS: return                      "Solaris";
  case AIX: return                          "AIX(Montery)";
  case IRIX: return                         "IRIX";
  case FREEBSD: return                      "FreeBSD";
  case TRU64: return                        "Tru64";
  case NOVELL_MODESTO: return               "Novell Modesto";
  case OPENBSD: return                      "OpenBSD";
  case OPENVMS: return                      "OpenVMS";
  case NONSTOP_KERNEL: return               "NonStop Kernel";
  case AROS: return                         "AROS";
  case FENIXOS: return                      "FenixOS";
  case NUXI_CLOUDABI: return                "Nuxi CloudABI";
  case STRATUS_TECHNOLOGIES_OPENVOS: return "Stratus Technologies OpenVOS";
  default: return                           "n/a";
  }
}

static const char *
elf_type_as_string(enum ELFType t) {
  switch (t) {
  case REL: return                 "Relocatable file";
  case EXEC: return                "Executable file";
  case DYN: return                 "Shared object";
  case CORE: return                "Core file";
  case LOOS: case HIOS: return     "Reserved inclusive range (Operating system specific)";
  case LOPROC: case HIPROC: return "Reserved inclusive range (Processor specific)";
  case NONE: default: return       "Unknown";
  }
}

static const char *
isa_as_string(enum ISA isa) {
  switch (isa) {
  case ATT_WE_32100: return                       "AT&T WE 32100";
  case SPARC: return                              "SPARC";
  case X86: return                                "x86";
  case MOTOROLA_MK68K: return                     "Motorola 68000 (M68k)";
  case MOTOROLA_MK88K: return                     "Motorola 88000 (M88k)";
  case INTEL_MCU: return                          "Intel MCU";
  case INTEL_80860: return                        "Intel 80860";
  case MIPS: return                               "MIPS";
  case IBM_SYSTEM_370: return                     "IBM System/370";
  case MIPBS_RS3000_LE: return                    "IBM System/370";
  case HP_PA_RISC: return                         "Hewlett-Packard PA-RISC";
  case INTEL_80960: return                        "Intel 80960";
  case POWER_PC: return                           "PowerPC";
  case POWER_PC_64: return                        "PowerPC (64-bit)";
  case S390: return                               "S390, including S390x";
  case IBM_SPU_SPC: return                        "IBM SPU/SPC";
  case NEC_V800: return                           "NEC V800";
  case FUJITSU_FR20: return                       "Fujitsu FR20";
  case TRW_RH_32: return                          "TRW RH-32";
  case MOTOROLA_RCE: return                       "Motorola RCE";
  case ARM: return                                "Arm (up to Armv7/AArch32)";
  case DIGITAL_ALPHA: return                      "Digital Alpha";
  case SUPER_H: return                            "SuperH";
  case SPARC_V_9: return                          "SPARC Version 9";
  case SIEMENS_TRICORE_EMBEDDED_PROCESSOR: return "Siemens TriCore embedded processor";
  case ARGONAUT_RISC_CORE: return                 "Argonaut RISC Core";
  case HITACHI_H8_300: return                     "Hitachi H8/300";
  case HITACHI_H8_300H: return                    "Hitachi H8/300H";
  case HITACHI_H8S: return                        "Hitachi H8S";
  case HITACHI_H8_500: return                     "Hitachi H8/500";
  case IA_64: return                              "IA-64";
  case STANFORD_MIPS_X: return                    "Stanford MIPS-X";
  case MOTOROLA_COLD_FIRE: return                 "Motorola ColdFire";
  case MOTOROLA_M68HC12: return                   "Motorola M68HC12";
  case FUJITSU_MMA: return                        "Fujitsu MMA Multimedia Accelerator";
  case SIEMENS_PCP: return                        "Siemens PCP";
  case SONY_NCPU_EMBEDDED_RISC_PROCESSOR: return  "Sony nCPU embedded RISC processor";
  case DENSO_NDR1: return                         "Denso NDR1 microprocessor";
  case MOTOROLA_STAR_CORE: return                 "Motorola Star*Core processor";
  case TOYOTA_ME16: return                        "Toyota ME16 processor";
  case STMICROELECTRONICS_ST100: return           "STMicroelectronics ST100 processor";
  case ADVANDE_LOGIC_CORP_TINYJ: return           "Advanced Logic Corp. TinyJ embedded processor family";
  case AMD_X86_64: return                         "AMD x86-64";
  case SONY_DSP: return                           "Sony DSP Processor";
  case DIGITAL_EQUIPMENT_CORP_PDP_10: return "    Digital Equipment Corp. PDP-10";
  case DIGITAL_EQUIPMENT_CORP_PDP_11: return "    Digital Equipment Corp. PDP-11";
  case SIEMENS_FX66: return                       "Siemens FX66 microcontroller";
  case STMICROELECTRONICS_ST9: return             "STMicroelectronics ST9+ 8/16 bit microcontroller";
  case STMICROELECTRONICS_ST7: return             "STMicroelectronics ST7 8-bit microcontroller";
  case MOTOROLA_MC68HC16: return                  "Motorola MC68HC16 Microcontroller";
  case MOTOROLA_MC68HC11: return                  "Motorola MC68HC11 Microcontroller";
  case MOTOROLA_MC68HC08: return                  "Motorola MC68HC08 Microcontroller";
  case MOTOROLA_MC68HC05: return                  "Motorola MC68HC05 Microcontroller";
  case SILICON_GRAPHICS_SVX: return               "Silicon Graphics SVx";
  case STMICROELECTRONICS_ST19: return            "STMicroelectronics ST19 8-bit microcontroller";
  case DIGITAL_VAX: return                        "Digital VAX";
  case AXIS_COMS_32: return                       "Axis Communications 32-bit embedded processor";
  case INFINEON_TECHS_32: return                  "Infineon Technologies 32-bit embedded processor";
  case ELEMENT_14_DSP: return                     "Element 14 64-bit DSP Processor";
  case LSI_LOGIC_DSP: return                      "LSI Logic 16-bit DSP Processor";
  case TMS320C6000: return                        "TMS320C6000 Family";
  case MCST_ELBRUS_E2K: return                    "MCST Elbrus e2k";
  case ARM_64: return                             "Arm 64-bits (Armv8/AArch64)";
  case ZILOG_Z8: return                           "Zilog Z80";
  case RISC_V: return                             "RISC-V";
  case BERKELEY_PACKET_FILTER: return             "Berkeley Packet Filter";
  case WDC_65C816: return                         "WDC 65C816";
  case LOONG_ARCH: return                         "LoongArch";
  case NO: default:
    return "n/a";
  }
}

static bool
is_valid_elf_header(u8 m, u8 e, u8 l, u8 f) {
  return m == 0x7F && e == 'E' && l == 'L' && f == 'F';
}

static bool
get_bit_format(enum BitFormat *bf, u8 bf_buf) {
  if (bf_buf > 2 || bf_buf < 1) return false;
  *bf = bf_buf;
  return true;
}

static bool
is_32_bit(enum BitFormat bf) {
  return bf == BIT32;
}

static bool
get_endianness(enum Endianness *e, u8 buf) {
  if (buf > 2 || buf < 1) return false;
  *e = buf;
  return true;
}

static bool
get_target_abi(enum TargetABI *abi, u8 buf) {
  if (buf > 0x12)
    return false;
  *abi = buf;
  return true;
}

static bool
get_elf_type(enum ELFType *ef, u8 buf1, u8 buf2) {
  uint16_t type = (buf2 << 8) + buf1;
  if (!elf_type_is_valid(type))
    return false;
  *ef = type;
  return true;
}

static bool
get_isa(enum ISA *isa, u8 buf1, u8 buf2) {
  uint16_t id = (buf2 << 8) + buf1;
  if (!isa_is_valid(id))
    return false;
  *isa = id;
  return true;
}

static bool
parse_elf(struct ELF *elf, char *filename) {
  int fd;
  size_t length;
  u8 *addr;
  struct stat sb;
  if ((fd = open(filename, O_RDONLY)) < 0) {
    perror("open");
    return false;
  }

  if (fstat(fd, &sb) < 0) {
    perror("fstat");
    return false;
  }
  length = sb.st_size;

  addr = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
  if (addr == MAP_FAILED) {
    perror("mmap");
    return false;
  }

  if (length < 5) {
    printf("File not ELF\n");
    return false;
  }
  if (!is_valid_elf_header(addr[0], addr[1], addr[2], addr[3])) {
    printf("File is not ELF\n");
    return false;
  }

  if (!get_bit_format(&elf->bf, addr[4])) {
    printf("Invalid bit format\n");
    return false;
  }

  if (length < (is_32_bit(elf->bf) ? 52 : 64)) {
      printf("Invalid ELF header");
      return false;
  }

  if (!get_endianness(&elf->end, addr[0x05])) {
    printf("Invalid endianess\n");
    return false;
  }

  elf->is_og = addr[0x06] == 1;

  if (!get_target_abi(&elf->abi, addr[0x07])) {
    printf("Invalid ABI\n");
    return false;
  }

  if (!get_elf_type(&elf->type, addr[0x10], addr[0x11])) {
    printf("Invalid ELF type\n");
    return false;
  }

  if (!get_isa(&elf->isa, addr[0x12], addr[0x13])) {
    printf("Invalid ISA\n");
    return false;
  }

  switch (elf->bf) {
  case BIT32:
    elf->entry = EXTRACT_32_BITS(addr, 0x18);
    printf("TODO");
    return false;
    break;
  case BIT64:
    elf->entry        = EXTRACT_64_BITS(addr, 0x18);
    elf->ph.offset    = EXTRACT_64_BITS(addr, 0x20);
    elf->sh.offset    = EXTRACT_64_BITS(addr, 0x28);
    elf->ph.size      = addr[0x36] + (addr[0x36 + 1] << 8);
    elf->ph.entries   = addr[0x38] + (addr[0x38 + 1] << 8);
    elf->sh.size      = addr[0x3A] + (addr[0x3A + 1] << 8);
    elf->sh.entries   = addr[0x3C] + (addr[0x3C + 1] << 8);
    elf->sh.str_index = addr[0x3E] + (addr[0x3E + 1] << 8);

    if (elf->ph.size != 0x38) {
      printf("Program header entry size is not 0x38, too complicated for me\n");
      return false;
    }

    if (elf->sh.size != 0x40) {
      printf("Section header entry size is not 0x40, too complicated for me\n");
      return false;
    }

    struct ProgramHeaderEntry *ph_entries = malloc(sizeof(struct ProgramHeaderEntry) * elf->ph.entries);
    if (ph_entries == NULL) {
      printf("Failed to allocate program header entries\n");
      return false;
    }
    size_t ph_offset = elf->ph.offset;
    for (int i = 0; i < elf->ph.entries; i++) {
      if (ph_offset + 0x38 > length) {
        printf("Program header entry missing\n");
        return false;
      }

      if (!phe_type_is_valid(EXTRACT_32_BITS(addr, ph_offset))) {
        printf("Invalid program header type: 0x%X\n", EXTRACT_32_BITS(addr, ph_offset));
        return false;
      }
      ph_entries[i].type = EXTRACT_32_BITS(addr, ph_offset);
      ph_entries[i].flags         = EXTRACT_32_BITS(addr, ph_offset + 0x04);
      ph_entries[i].offset        = EXTRACT_64_BITS(addr, ph_offset + 0x08);
      ph_entries[i].virtual_addr  = EXTRACT_64_BITS(addr, ph_offset + 0x10);
      ph_entries[i].physical_addr = EXTRACT_64_BITS(addr, ph_offset + 0x18);
      ph_entries[i].file_size     = EXTRACT_64_BITS(addr, ph_offset + 0x20);
      ph_entries[i].mem_size      = EXTRACT_64_BITS(addr, ph_offset + 0x28);
      ph_entries[i].align         = EXTRACT_64_BITS(addr, ph_offset + 0x30);

      ph_offset += 0x38;
    }
    elf->ph.entries_ptr = ph_entries;

    struct SectionHeaderEntry *sh_entries = malloc(sizeof(struct SectionHeaderEntry) * elf->sh.entries);
    if (sh_entries == NULL) {
      printf("Failed to allocate section header entries\n");
      return false;
    }
    size_t sh_offset = elf->sh.offset;
    for (int i = 0; i < elf->sh.entries; i++) {
      if (sh_offset + 0x40 > length) {
        printf("Section header entry missing\n");
        return false;
      }

      sh_entries[i].str_offset = EXTRACT_32_BITS(addr, sh_offset);

      if (!she_type_is_valid(EXTRACT_32_BITS(addr, sh_offset + 0x04))) {
        printf("Invalid section header type: 0x%X\n", EXTRACT_32_BITS(addr, sh_offset + 0x04));
        return false;
      }
      sh_entries[i].type = EXTRACT_32_BITS(addr, sh_offset + 0x04);
      sh_entries[i].flags = EXTRACT_64_BITS(addr, sh_offset + 0x08);
      sh_entries[i].addr = EXTRACT_64_BITS(addr, sh_offset + 0x10);
      sh_entries[i].offset = EXTRACT_64_BITS(addr, sh_offset + 0x18);
      sh_entries[i].size = EXTRACT_64_BITS(addr, sh_offset + 0x20);
      sh_entries[i].link = EXTRACT_32_BITS(addr, sh_offset + 0x28);
      sh_entries[i].info = EXTRACT_32_BITS(addr, sh_offset + 0x2C);
      sh_entries[i].addralign = EXTRACT_64_BITS(addr, sh_offset + 0x30);
      sh_entries[i].entries_size = EXTRACT_64_BITS(addr, sh_offset + 0x38);

      sh_offset += 0x40;
    }
    elf->sh.entries_ptr = sh_entries;
    break;
  default:
    break;
  }

  close(fd);
  return true;
}

static void
elf_cleanup(struct ELF *elf) {
  if (elf->ph.entries_ptr != NULL)
    free(elf->ph.entries_ptr);
  if (elf->sh.entries_ptr != NULL)
    free(elf->sh.entries_ptr);
}

int
main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  struct ELF elf;
  elf.ph.entries_ptr = NULL;
  elf.sh.entries_ptr = NULL;
  if (!parse_elf(&elf, "a.out"))
    return 1;

  printf("Addressing format : %s\n", bit_format_as_string(elf.bf));
  printf("Endianness        : %s\n", endianness_as_string(elf.end));
  printf("Target ABI        : %s\n", target_abi_as_string(elf.abi));
  printf("OBJ file type     : %s\n", elf_type_as_string(elf.type));
  printf("ISA               : %s\n", isa_as_string(elf.isa));
  printf("Entry             : 0x%lX\n", elf.entry);

  for (int i = 0; i < elf.ph.entries; i++) {
    printf("\n################## Program header entry\n");
    printf("\n");
  }

  for (int i = 0; i < elf.sh.entries; i++) {
    printf("\n################## Section header entry\n");
    printf("\n");
  }

  elf_cleanup(&elf);

  return 0;
}
