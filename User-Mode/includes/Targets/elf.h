/*
 *
 *  Copyright (C) 2013  Anwar Mohamed <anwarelmakrahy[at]gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to Anwar Mohamed
 *  anwarelmakrahy[at]gmail.com
 *
 */

#ifndef ELF_H
#define ELF_H

#define Elf32_Addr unsigned int
#define Elf32_Half unsigned short int
#define Elf32_Off unsigned int
#define Elf32_Sword int
#define Elf32_Word unsigned int

/*e_ident[] Identification Indexes*/
#define EI_MAG0		0	//File identification
#define EI_MAG1		1	//File identification
#define EI_MAG2		2	//File identification
#define EI_MAG3	    3	//File identification
#define EI_CLASS	4	//File class
#define EI_DATA	    5	//Data encoding
#define EI_VERSION	6	//File version
#define EI_NIDENT	16	//Size of e_ident[]

/*e_type*/
#define ET_NONE         0  //No file type
#define ET_REL          1  //Relocatable file
#define ET_EXEC         2  //Executable file
#define ET_DYN          3  //Shared object file
#define ET_CORE         4  //Core file
#define ET_LOPROC  0xff00  //Processor-specific
#define ET_HIPROC  0xffff  //Processor-specific

/*e_machine*/
#define EM_NONE		0	//No machine
#define EM_M32      1	//AT&T WE 32100
#define EM_SPARC    2	//SPARC
#define EM_386      3	//Intel 80386
#define EM_68K      4	//Motorola 68000
#define EM_88K      5	//Motorola 88000
#define EM_860      7	//Intel 80860
#define EM_MIPS     8	//MIPS RS3000

/*e_version*/
#define EV_NONE     0	//Invalid version
#define EV_CURRENT  1	//Current version

/*EI_CLASS*/
#define ELFCLASSNONE	0	//Invalid class
#define ELFCLASS32      1	//32-bit objects
#define ELFCLASS64      2	//64-bit objects

/*EI_DATA*/
#define ELFDATANONE		0	//Invalid data encoding
#define ELFDATA2LSB     1
#define ELFDATA2MSB     2

/*ELF Header*/
struct elf32_header {
	unsigned char e_ident[EI_NIDENT];
	Elf32_Half	e_type;
	Elf32_Half	e_machine;
	Elf32_Word	e_version;
	Elf32_Addr	e_entry;
	Elf32_Off	e_phoff;
	Elf32_Off	e_shoff;
	Elf32_Word	e_flags;
	Elf32_Half	e_ehsize;
	Elf32_Half	e_phentsize;
	Elf32_Half	e_phnum;
	Elf32_Half	e_shentsize;
	Elf32_Half	e_shnum;
	Elf32_Half	e_shstrndx;
};

struct elf32_section_header {
	Elf32_Word	sh_name;
	Elf32_Word	sh_type;
	Elf32_Word	sh_flags;
	Elf32_Addr	sh_addr;
	Elf32_Off	sh_offset;
	Elf32_Word	sh_size;
	Elf32_Word	sh_link;
	Elf32_Word	sh_info;
	Elf32_Word	sh_addralign;
	Elf32_Word	sh_entsize;
};

struct elf32_program_header {
	Elf32_Word p_type;
	Elf32_Off  p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf32_Word p_filesz;
	Elf32_Word p_memsz;
	Elf32_Word p_flags;
	Elf32_Word p_align;
};



/* sh_type */
#define	SHT_NULL			0		
#define	SHT_PROGBITS		1
#define	SHT_SYMTAB			2
#define	SHT_STRTAB			3
#define	SHT_RELA			4
#define	SHT_HASH			5
#define	SHT_DYNAMIC			6
#define	SHT_NOTE			7
#define	SHT_NOBITS			8
#define	SHT_REL				9
#define	SHT_SHLIB			10
#define	SHT_DYNSYM			11
#define	SHT_UNKNOWN12		12
#define	SHT_UNKNOWN13		13
#define	SHT_INIT_ARRAY		14
#define	SHT_FINI_ARRAY		15
#define	SHT_PREINIT_ARRAY	16
#define	SHT_GROUP			17
#define	SHT_SYMTAB_SHNDX	18


struct Elf32_Sym {
	Elf32_Word    st_name;
	Elf32_Addr    st_value;
	Elf32_Word    st_size;
	unsigned char st_info;
	unsigned char st_other;
	Elf32_Half    st_shndx;
};

struct Elf32_Dyn 
{
	Elf32_Sword d_tag;
	union {
		Elf32_Word	d_val;
		Elf32_Addr	d_ptr;
		Elf32_Off   d_off;
	} d_un;
} ;

#define DT_NULL			0				//ignored	 mandatory    mandatory
#define DT_NEEDED		1				//d_val	 optional     optional
#define DT_PLTRELSZ		2				//d_val	 optional     optional
#define DT_PLTGOT		3				//d_ptr	 optional     optional
#define DT_HASH			4				//d_ptr	 mandatory    mandatory
#define DT_STRTAB		5				//d_ptr	 mandatory    mandatory
#define DT_SYMTAB		6				//d_ptr	 mandatory    mandatory
#define DT_RELA			7				//d_ptr	 mandatory    optional
#define DT_RELASZ		8				//d_val	 mandatory    optional
#define DT_RELAENT		9				//d_val	 mandatory    optional
#define DT_STRSZ		10				//d_val	 mandatory    mandatory
#define DT_SYMENT		11				//d_val	 mandatory    mandatory
#define DT_INIT			12				//d_ptr	 optional     optional
#define DT_FINI			13				//d_ptr	 optional     optional
#define DT_SONAME		14				//d_val	 ignored      optional
#define DT_RPATH		15				//d_val	 optional     ignored
#define DT_SYMBOLIC		16				//ignored	 ignored      optional
#define DT_REL			17				//d_ptr	 mandatory    optional
#define DT_RELSZ		18				//d_val	 mandatory    optional
#define DT_RELENT		19				//d_val	 mandatory    optional
#define DT_PLTREL		20				//d_val	 optional     optional
#define DT_DEBUG		21				//d_ptr	 optional     ignored
#define DT_TEXTREL		22				//ignored	 optional     optional
#define DT_JMPREL		23				//d_ptr	 optional     optional
#define DT_BIND_NOW		24				/* Bind now regardless of env setting */
#define DT_NUM			25				/* Number used. */	
#define DT_GNU_HASH		0x6ffffef5			/* address of gnu-style symbol hash table */	
#define DT_LOPROC		0x70000000			/* reserved range for processor */
#define DT_HIPROC		0x7fffffff			/*  specific dynamic array tags */

#define EI_MAG0		0		/* file ID */
#define EI_MAG1		1		/* file ID */
#define EI_MAG2		2		/* file ID */
#define EI_MAG3		3		/* file ID */
#define EI_CLASS	4		/* file class */
#define EI_DATA		5		/* data encoding */
#define EI_VERSION	6		/* ELF header version */
#define EI_OSABI	7		/* OS/ABI ID */
#define EI_ABIVERSION	8		/* ABI version */ 
#define EI_PAD		9		/* start of pad bytes */
#define EI_NIDENT	16		/* Size of e_ident[] */

/* e_ident[] magic number */
#define	ELFMAG0		0x7f		/* e_ident[EI_MAG0] */
#define	ELFMAG1		'E'		/* e_ident[EI_MAG1] */
#define	ELFMAG2		'L'		/* e_ident[EI_MAG2] */
#define	ELFMAG3		'F'		/* e_ident[EI_MAG3] */
#define	ELFMAG		"\177ELF"	/* magic */
#define	SELFMAG		4		/* size of magic */

/* e_ident[] file class */
#define	ELFCLASSNONE	0		/* invalid */
#define	ELFCLASS32	1		/* 32-bit objs */
#define	ELFCLASS64	2		/* 64-bit objs */
#define	ELFCLASSNUM	3		/* number of classes */

/* e_ident[] data encoding */
#define ELFDATANONE	0		/* invalid */
#define ELFDATA2LSB	1		/* Little-Endian */
#define ELFDATA2MSB	2		/* Big-Endian */
#define ELFDATANUM	3		/* number of data encode defines */

/* e_ident[] Operating System/ABI */
#define ELFOSABI_SYSV		0	/* UNIX System V ABI */
#define ELFOSABI_HPUX		1	/* HP-UX operating system */
#define ELFOSABI_NETBSD		2	/* NetBSD */
#define ELFOSABI_LINUX		3	/* GNU/Linux */
#define ELFOSABI_HURD		4	/* GNU/Hurd */
#define ELFOSABI_86OPEN		5	/* 86Open common IA32 ABI */
#define ELFOSABI_SOLARIS	6	/* Solaris */
#define ELFOSABI_MONTEREY	7	/* Monterey */
#define ELFOSABI_IRIX		8	/* IRIX */
#define ELFOSABI_FREEBSD	9	/* FreeBSD */
#define ELFOSABI_TRU64		10	/* TRU64 UNIX */
#define ELFOSABI_MODESTO	11	/* Novell Modesto */
#define ELFOSABI_OPENBSD	12	/* OpenBSD */
#define ELFOSABI_ARM		97	/* ARM */
#define ELFOSABI_STANDALONE	255	/* Standalone (embedded) application */

/* e_ident */
#define IS_ELF(ehdr) ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
                      (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
                      (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
                      (ehdr).e_ident[EI_MAG3] == ELFMAG3)

/* e_type */
#define ET_NONE		0		/* No file type */
#define ET_REL		1		/* relocatable file */
#define ET_EXEC		2		/* executable file */
#define ET_DYN		3		/* shared object file */
#define ET_CORE		4		/* core file */
#define ET_NUM		5		/* number of types */
#define ET_LOPROC	0xff00		/* reserved range for processor */
#define ET_HIPROC	0xffff		/*  specific e_type */

/* e_machine */
#define EM_NONE		0		/* No Machine */
#define EM_M32		1		/* AT&T WE 32100 */
#define EM_SPARC	2		/* SPARC */
#define EM_386		3		/* Intel 80386 */
#define EM_68K		4		/* Motorola 68000 */
#define EM_88K		5		/* Motorola 88000 */
#define EM_486		6		/* Intel 80486 - unused? */
#define EM_860		7		/* Intel 80860 */
#define EM_MIPS		8		/* MIPS R3000 Big-Endian only */
/* 
 * Don't know if EM_MIPS_RS4_BE,
 * EM_SPARC64, EM_PARISC,
 * or EM_PPC are ABI compliant
 */
#define EM_MIPS_RS4_BE	10		/* MIPS R4000 Big-Endian */
#define EM_SPARC64	11		/* SPARC v9 64-bit unoffical */
#define EM_PARISC	15		/* HPPA */
#define EM_SPARC32PLUS	18		/* Enhanced instruction set SPARC */
#define EM_PPC		20		/* PowerPC */
#define EM_ARM		40		/* Advanced RISC Machines ARM */
#define EM_ALPHA	41		/* DEC ALPHA */
#define EM_SPARCV9	43		/* SPARC version 9 */
#define EM_ALPHA_EXP	0x9026		/* DEC ALPHA */
#define EM_AMD64	62		/* AMD64 architecture */
#define EM_VAX		75		/* DEC VAX */
#define EM_NUM		15		/* number of machine types */

/* Version */
#define EV_NONE		0		/* Invalid */
#define EV_CURRENT	1		/* Current */
#define EV_NUM		2		/* number of versions */


/* Special Section Indexes */
#define SHN_UNDEF	0		/* undefined */
#define SHN_LORESERVE	0xff00		/* lower bounds of reserved indexes */
#define SHN_LOPROC	0xff00		/* reserved range for processor */
#define SHN_HIPROC	0xff1f		/*   specific section indexes */
#define SHN_ABS		0xfff1		/* absolute value */
#define SHN_COMMON	0xfff2		/* common symbol */
#define SHN_HIRESERVE	0xffff		/* upper bounds of reserved indexes */

/* sh_type */
#define SHT_NULL	0		/* inactive */
#define SHT_PROGBITS	1		/* program defined information */
#define SHT_SYMTAB	2		/* symbol table section */
#define SHT_STRTAB	3		/* string table section */
#define SHT_RELA	4		/* relocation section with addends*/
#define SHT_HASH	5		/* symbol hash table section */
#define SHT_DYNAMIC	6		/* dynamic section */
#define SHT_NOTE	7		/* note section */
#define SHT_NOBITS	8		/* no space section */
#define SHT_REL		9		/* relation section without addends */
#define SHT_SHLIB	10		/* reserved - purpose unknown */
#define SHT_DYNSYM	11		/* dynamic symbol table section */
#define SHT_NUM		12		/* number of section types */
#define SHT_GNU_HASH	0x6ffffff6	/* GNU-style symbol hash table section  */
#define SHT_GNU_VERNEED 0x6ffffffe
#define SHT_LOPROC	0x70000000	/* reserved range for processor */
#define SHT_HIPROC	0x7fffffff	/*  specific section header types */
#define SHT_LOUSER	0x80000000	/* reserved range for application */
#define SHT_HIUSER	0xffffffff	/*  specific indexes */

/* Section names */
#define ELF_BSS         ".bss"		/* uninitialized data */
#define ELF_DATA        ".data"		/* initialized data */
#define ELF_DEBUG       ".debug"	/* debug */
#define ELF_DYNAMIC     ".dynamic"	/* dynamic linking information */
#define ELF_DYNSTR      ".dynstr"	/* dynamic string table */
#define ELF_DYNSYM      ".dynsym"	/* dynamic symbol table */
#define ELF_FINI        ".fini"		/* termination code */
#define ELF_GOT         ".got"		/* global offset table */
#define ELF_HASH        ".hash"		/* symbol hash table */
#define ELF_INIT        ".init"		/* initialization code */
#define ELF_REL_DATA    ".rel.data"	/* relocation data */
#define ELF_REL_FINI    ".rel.fini"	/* relocation termination code */
#define ELF_REL_INIT    ".rel.init"	/* relocation initialization code */
#define ELF_REL_DYN     ".rel.dyn"	/* relocaltion dynamic link info */
#define ELF_REL_RODATA  ".rel.rodata"	/* relocation read-only data */
#define ELF_REL_TEXT    ".rel.text"	/* relocation code */
#define ELF_RODATA      ".rodata"	/* read-only data */
#define ELF_SHSTRTAB    ".shstrtab"	/* section header string table */
#define ELF_STRTAB      ".strtab"	/* string table */
#define ELF_SYMTAB      ".symtab"	/* symbol table */
#define ELF_TEXT        ".text"		/* code */

/* Section Attribute Flags - sh_flags */
#define SHF_WRITE	0x1		/* Writable */
#define SHF_ALLOC	0x2		/* occupies memory */
#define SHF_EXECINSTR	0x4		/* executable */
#define SHF_MASKPROC	0xf0000000	/* reserved bits for processor */
					/*  specific section attributes */

/* Symbol table index */
#define STN_UNDEF	0		/* undefined */

/* Extract symbol info - st_info */
#define ELF32_ST_BIND(x)	((x) >> 4)
#define ELF32_ST_TYPE(x)	(((unsigned int) x) & 0xf)
#define ELF32_ST_INFO(b,t)	(((b) << 4) + ((t) & 0xf))

#define ELF64_ST_BIND(x)	((x) >> 4)
#define ELF64_ST_TYPE(x)	(((unsigned int) x) & 0xf)
#define ELF64_ST_INFO(b,t)	(((b) << 4) + ((t) & 0xf))

/* Symbol Binding - ELF32_ST_BIND - st_info */
#define STB_LOCAL	0		/* Local symbol */
#define STB_GLOBAL	1		/* Global symbol */
#define STB_WEAK	2		/* like global - lower precedence */
#define STB_NUM		3		/* number of symbol bindings */
#define STB_LOPROC	13		/* reserved range for processor */
#define STB_HIPROC	15		/*  specific symbol bindings */

/* Symbol type - ELF32_ST_TYPE - st_info */
#define STT_NOTYPE	0		/* not specified */
#define STT_OBJECT	1		/* data object */
#define STT_FUNC	2		/* function */
#define STT_SECTION	3		/* section */
#define STT_FILE	4		/* file */
#define STT_NUM		5		/* number of symbol types */
#define STT_LOPROC	13		/* reserved range for processor */
#define STT_HIPROC	15		/*  specific symbol types */


/* Extract relocation info - r_info */
#define ELF32_R_SYM(i)		((i) >> 8)
#define ELF32_R_TYPE(i)		((unsigned char) (i))
#define ELF32_R_INFO(s,t) 	(((s) << 8) + (unsigned char)(t))

/* Segment types - p_type */
#define PT_NULL		0		/* unused */
#define PT_LOAD		1		/* loadable segment */
#define PT_DYNAMIC	2		/* dynamic linking section */
#define PT_INTERP	3		/* the RTLD */
#define PT_NOTE		4		/* auxiliary information */
#define PT_SHLIB	5		/* reserved - purpose undefined */
#define PT_PHDR		6		/* program header */
#define PT_NUM		7		/* Number of segment types */
#define PT_LOOS		0x60000000	/* reserved range for OS */
#define PT_HIOS		0x6fffffff	/*  specific segment types */
#define PT_LOPROC	0x70000000	/* reserved range for processor */
#define PT_HIPROC	0x7fffffff	/*  specific segment types */

/* Segment flags - p_flags */
#define PF_X		0x1		/* Executable */
#define PF_W		0x2		/* Writable */
#define PF_R		0x4		/* Readable */
#define PF_MASKPROC	0xf0000000	/* reserved bits for processor */
					/*  specific segment flags */

/* Dynamic Array Tags - d_tag */
#define DT_NULL		0		/* marks end of _DYNAMIC array */
#define DT_NEEDED	1		/* string table offset of needed lib */
#define DT_PLTRELSZ	2		/* size of relocation entries in PLT */
#define DT_PLTGOT	3		/* address PLT/GOT */
#define DT_HASH		4		/* address of symbol hash table */
#define DT_STRTAB	5		/* address of string table */
#define DT_SYMTAB	6		/* address of symbol table */
#define DT_RELA		7		/* address of relocation table */
#define DT_RELASZ	8		/* size of relocation table */
#define DT_RELAENT	9		/* size of relocation entry */
#define DT_STRSZ	10		/* size of string table */
#define DT_SYMENT	11		/* size of symbol table entry */
#define DT_INIT		12		/* address of initialization func. */
#define DT_FINI		13		/* address of termination function */
#define DT_SONAME	14		/* string table offset of shared obj */
#define DT_RPATH	15		/* string table offset of library
					   search path */
#define DT_SYMBOLIC	16		/* start sym search in shared obj. */
#define DT_REL		17		/* address of rel. tbl. w addends */
#define DT_RELSZ	18		/* size of DT_REL relocation table */
#define DT_RELENT	19		/* size of DT_REL relocation entry */
#define DT_PLTREL	20		/* PLT referenced relocation entry */
#define DT_DEBUG	21		/* bugger */
#define DT_TEXTREL	22		/* Allow rel. mod. to unwritable seg */
#define DT_JMPREL	23		/* add. of PLT's relocation entries */
#define DT_BIND_NOW	24		/* Bind now regardless of env setting */
#define DT_NUM		25		/* Number used. */
#define DT_GNU_HASH	0x6ffffef5	/* address of gnu-style symbol hash table */
#define DT_LOPROC	0x70000000	/* reserved range for processor */
#define DT_HIPROC	0x7fffffff	/*  specific dynamic array tags */
#define DT_VERSYM   0x6ffffff0
	

struct elf32_rel 
{
	Elf32_Addr    r_offset;
	Elf32_Word    r_info;
};


#endif
