#include "core.h"

namespace {
	pe::loader_t dll;
	beep_func_t beep;
};

int main( int argc, char *argv[], char *envp[] ){

	dll.open( "testing-dll.dll" );
	dll.load();

	beep = (beep_func_t)dll.proc_address( "test_beep" );
	if( beep ){
		beep( MB_HELP );
	};

	dll.close();

	return 0;
};
