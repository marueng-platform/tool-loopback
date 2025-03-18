//
// Created by Shin on 2019-12-01.
// Copyright (C) 2019. Marueng. All rights reserved.
//
#pragma once
#include <stdio.h>
#include <string.h>
typedef unsigned char UINT_8;
typedef unsigned int UINT_32;
typedef int INT_32;
typedef long long UINT_64;

class CBitcalc  
{
public:
	CBitcalc(UINT_8 *pData);
	virtual ~CBitcalc();

	UINT_8 *m_pData;
	int m_BitCount;

	UINT_32 GetData(int bitSize);
	UINT_64 GetData64(int bitSize);
	UINT_32 GetCurrentBitCount();
	UINT_32 GetCurrentCount();
	void SetByteAlign();
	UINT_32 GetExpandableLen();
	void SkipData(int bitCount);
	void GetByteData(int len,UINT_8 *pData);
	void NewSession(UINT_8 *pData);

	// Exponential Golomb Code
	UINT_32 GetExpGolmbValue(UINT_32 *Len);
	UINT_32 GetExpGolmbValue();
	INT_32 GetSignedExpGolmbValue();

	// Data Making
	void SetBit(UINT_32 bit);
	void SetData(int bitSize, UINT_32 data);
	void SetData64(int bitSize, UINT_64 data);
	void SetBitWithPos(int pos,UINT_32 bit);
	void SetDataWithPos(int pos,int bitSize, UINT_32 data);
	void SetByteData(int len, UINT_8 *pData);
    void SetByteDataAligned(int len, UINT_8 *pData);
};
