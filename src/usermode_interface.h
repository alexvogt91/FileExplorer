
// usermode_interface.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'pch.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CusermodeinterfaceApp:
// See usermode_interface.cpp for the implementation of this class
//

class CusermodeinterfaceApp : public CWinApp
{
public:
	CusermodeinterfaceApp();

// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CusermodeinterfaceApp theApp;
