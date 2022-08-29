#pragma once

#include "../win_hdrs/win_types.h"

#include "../win_hdrs/pshpack4.h" // ensure that 4 byte packing (the default) is used 

namespace pe {

/*
 * Rich header format.
 */

const DWORD RICH_HDR_MAGIC = 0x68636952; //"Rich"
const DWORD DANS_HDR_MAGIC = 0x536E6144; //"DanS"

typedef struct _RICH_COMP_ID {
	WORD CV;
	WORD prodId;
	DWORD count;
} RICH_COMP_ID, *PRICH_COMP_ID;

typedef struct _RICH_SIGNATURE {
	DWORD   richId;
	DWORD   checksum;
} RICH_SIGNATURE, *PRICH_SIGNATURE;

typedef struct _RICH_DANS_HEADER {
	DWORD   dansId;
	DWORD   cPad[3];
	RICH_COMP_ID compId[1]; //several instances possible
} RICH_DANS_HEADER, *PRICH_DANS_HEADER;

typedef struct _IMAGE_RICH_HEADER {
	RICH_DANS_HEADER dansHdr;
	RICH_SIGNATURE richSign;
} IMAGE_RICH_HEADER, *PIMAGE_RICH_HEADER;


///---

//Debug Directory type: CodeView
#pragma pack (1)

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define CV_SIGNATURE_RSDS 0x53445352
#define CV_SIGNATURE_NB10 0x3031424E

typedef struct _RSDSI_GUID {
    DWORD Data1;
    WORD Data2;
    WORD Data3;
    BYTE Data4[2];
    BYTE Data5[6];
} RSDSI_GUID;


// CodeView header
struct CV_HEADER
{
    DWORD CvSignature; // NBxx
    LONG  Offset;      // Always 0 for NB10
};

typedef struct _DEBUG_NB10
{
    CV_HEADER  cvHdr;
    DWORD      Signature;       // seconds since 01.01.1970
    DWORD      Age;             // an always-incrementing value 
    BYTE       PdbFileName[1];  // zero terminated string with the name of the PDB file 
} DEBUG_NB10, *PDEBUG_NB10;

typedef struct _DEBUG_RSDSI
{
    /*000*/ DWORD dwSig;
    /*004*/ RSDSI_GUID  guidSig;
    /*014*/ DWORD age;
    /*018*/ BYTE  szPdb[1];
    /*324*/
} DEBUG_RSDSI, *PDEBUG_RSDSI;

#define RSDSI_SIZE sizeof (RSDSI)

#pragma pack () //#pragma pack (1)


}; //namespace pe

#include "../win_hdrs/poppack.h"
