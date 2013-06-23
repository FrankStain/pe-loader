#include "core.h"

BOOL WINAPI DllMain( HINSTANCE inst, DWORD reason, LPVOID tag ){
	switch( reason ){
		case DLL_PROCESS_ATTACH:
			DisableThreadLibraryCalls( inst );
			MessageBeep( MB_ICONEXCLAMATION );
		break;
		case DLL_PROCESS_DETACH:
			MessageBeep( MB_ICONEXCLAMATION );
		break;
	};

	return true;
};

EXPORT BOOL CALLBACK test_beep( DWORD message ){
	MessageBeep( message );
	return true;
};