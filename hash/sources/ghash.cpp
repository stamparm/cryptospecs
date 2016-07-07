/*
	---------------------------------------------------------------------------
	Copyright (c) 2003, Dominik Reichl <dominik.reichl@t-online.de>, Germany.
	All rights reserved.

	Distributed under the terms of the GNU General Public License v2.

	This software is provided 'as is' with no explicit or implied warranties
	in respect of its properties, including, but not limited to, correctness 
	and/or fitness for purpose.
	---------------------------------------------------------------------------
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ghash.h"

CGHash::CGHash()
{
	Init();
}

CGHash::~CGHash()
{
	Init();
}

void CGHash::Init()
{
	m_hash3 = 0;
	m_hash5 = 0;
}

void CGHash::Update(const unsigned char *pData, unsigned long uSize)
{
	unsigned long i = 0;

	for(i = 0; i < uSize; i++)
	{
		m_hash3 = (m_hash3 << 3) + m_hash3 + pData[i];
		m_hash5 = (m_hash5 << 5) + m_hash5 + pData[i];
	}
}

void CGHash::FinalToStr(char *strOutput, int nHash)
{
	// Do NOT destroy internal hash states here!

	if(nHash == 3)
	{
		sprintf(strOutput, "%02X%02X%02X%02X",
			(m_hash3 & 0xFF000000) >> 24,
			(m_hash3 & 0x00FF0000) >> 16,
			(m_hash3 & 0x0000FF00) >> 8,
			 m_hash3 & 0x000000FF);
	}

	if(nHash == 5)
	{
		sprintf(strOutput, "%02X%02X%02X%02X",
			(m_hash5 & 0xFF000000) >> 24,
			(m_hash5 & 0x00FF0000) >> 16,
			(m_hash5 & 0x0000FF00) >> 8,
			 m_hash5 & 0x000000FF);
	}
}
