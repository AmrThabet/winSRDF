// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>

//#if BUILDING_DLL
# define DLLIMPORT __declspec (dllexport)
//#else /* Not BUILDING_DLL */
//# define DLLIMPORT __declspec (dllimport)
//#endif /* Not BUILDING_DLL */

// TODO: reference additional headers your program requires here
