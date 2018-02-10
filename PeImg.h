#ifndef PE_IMG
#define PE_IMG

// preprocessors from usermode winapi winnt.h
#define IMAGE_DIRECTORY_ENTRY_IAT 12
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef long LONG;

// PE header structures from usermode winapi winnt.h

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;
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
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32, USERMODE_NT_HEADER, *PUSERMODE_NT_HEADER;

typedef struct _USERMODE_IMAGE_HEADER
{   
	WORD   e_magic;                
	WORD   e_cblp;                    
	WORD   e_cp;                     
	WORD   e_crlc;                    
	WORD   e_cparhdr;               
	WORD   e_minalloc;             
	WORD   e_maxalloc;          
	WORD   e_ss;                  
	WORD   e_sp;                 
	WORD   e_csum; 
	WORD   e_ip; 
	WORD   e_cs;  
	WORD   e_lfarlc;  
	WORD   e_ovno;                    
	WORD   e_res[4];        
	WORD   e_oemid; 
	WORD   e_oeminfo; 
	WORD   e_res2[10];  
	LONG   e_lfanew; 
} USERMODE_IMAGE_HEADER, *PUSERMODE_IMAGE_HEADER;

// Structure for import address table 

typedef struct _IMP_AT
{
	SIZE_T Size;
	PVOID Address;
} IMP_AT, IMPORT_ADDRESS_TABLE;

#endif
