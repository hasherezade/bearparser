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

}; //namespace pe

#include "../win_hdrs/poppack.h"
