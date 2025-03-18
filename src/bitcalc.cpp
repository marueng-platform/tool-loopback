//
// Created by Shin on 2019-12-01.
// Copyright (C) 2019. Marueng. All rights reserved.
//
#include "bitcalc.h"

CBitcalc::CBitcalc(UINT_8 *pData)
{
	m_pData = pData;
	m_BitCount = 0;
}

CBitcalc::~CBitcalc()
{

}

void CBitcalc::NewSession(UINT_8 *pData)
{
	m_pData = pData;
	m_BitCount = 0;
}

void CBitcalc::SetBit(UINT_32 bit)
{
	int UINT_8Count;
	int bitPos;
	UINT_8 ucTemp;

	UINT_8Count = (m_BitCount / 8);
	bitPos = m_BitCount % 8;
	
	if (bit)
	{
		ucTemp = 1 << (7-bitPos);
		m_pData[UINT_8Count] |= ucTemp;
	}
	else
	{
		ucTemp = ~(1 << (7-bitPos));
		m_pData[UINT_8Count] &= ucTemp;
	}

	m_BitCount++;
}

void CBitcalc::SetData(int bitSize, UINT_32 data)
{
	int i;

	for (i=0;i<bitSize;i++)
	{
		SetBit((data >> (bitSize-1-i)) & 0x01);
	}
}

void CBitcalc::SetData64(int bitSize, UINT_64 data)
{
	int i;

	for (i=0;i<bitSize;i++)
	{
		SetBit((data >> (bitSize-1-i)) & 0x01);
	}
}

void CBitcalc::SetBitWithPos(int pos,UINT_32 bit)
{
	int UINT_8Count;
	int bitPos;
	UINT_8 ucTemp;
	
	UINT_8Count = (pos / 8);
	bitPos = pos % 8;
	
	if (bit)
	{
		ucTemp = 1 << (7-bitPos);
		m_pData[UINT_8Count] |= ucTemp;
	}
	else
	{
		ucTemp = ~(1 << (7-bitPos));
		m_pData[UINT_8Count] &= ucTemp;
	}
}

void CBitcalc::SetDataWithPos(int pos,int bitSize, UINT_32 data)
{
	int i;
	int BitCount;

	BitCount = pos;
	for (i=0;i<bitSize;i++)
	{
		SetBitWithPos(BitCount,(data >> (bitSize-1-i)) & 0x01);
		BitCount++;
	}
}

void CBitcalc::SetByteData(int len, UINT_8 *pData)
{
	int i;

	for (i=0;i<len;i++)
	{
		SetData(8,(unsigned long)pData[i]);
	}
}

UINT_32 CBitcalc::GetData(int bitSize)
{
	int nCount;
	int remainBit;
	int calcBit;
	UINT_32 value = 0;
	int i;

	for (i=0;i<bitSize;i++)
	{
		nCount = (m_BitCount / 8);
		remainBit = (nCount+1) * 8 - m_BitCount;
		calcBit = (m_pData[nCount] >> (remainBit-1)) & 0x01;
		value = (value << 1) + calcBit;
		m_BitCount++;
	}
	
	return value;
}

UINT_64 CBitcalc::GetData64(int bitSize)
{
	int nCount;
	int remainBit;
	int calcBit;
	UINT_64 value = 0;
	int i;

	for (i=0;i<bitSize;i++)
	{
		nCount = (m_BitCount / 8);
		remainBit = (nCount+1) * 8 - m_BitCount;
		calcBit = (m_pData[nCount] >> (remainBit-1)) & 0x01;
		value = (value << 1) + calcBit;
		m_BitCount++;
	}
	
	return value;
}

void CBitcalc::SkipData(int bitCount)
{
	m_BitCount += bitCount;
}

UINT_32 CBitcalc::GetCurrentBitCount()
{
	return m_BitCount;
}

UINT_32 CBitcalc::GetCurrentCount()
{
    return m_BitCount/8;
}
void CBitcalc::SetByteAlign()
{
	m_BitCount = ((m_BitCount+7) / 8) * 8;
}

UINT_32 CBitcalc::GetExpandableLen()
{
	UINT_32 sizeOfInstance,temp;

	SetByteAlign();
	
	sizeOfInstance = 0;
	temp = GetData(8);
	if ((temp & 0x80) == 0)
	{
		sizeOfInstance = temp;
	}
	else
	{
		sizeOfInstance = (temp & 0x7F);
		while ((temp & 0x80) != 0) 
		{
			temp = GetData(8);
			sizeOfInstance = sizeOfInstance << 7 | (temp & 0x7F);
		}
	}

	return sizeOfInstance;
}

UINT_32 CBitcalc::GetExpGolmbValue(UINT_32 *Len)
{
	UINT_32 bit;
	int nCount;
	UINT_32 val;

	nCount = 0;
	bit = GetData(1);
	while (bit == 0)
	{
		bit = GetData(1);
		nCount++;
	}

	val = ((((int)1) << nCount) - 1) + GetData(nCount);

	*Len = nCount*2+1;

	return val;
}

UINT_32 CBitcalc::GetExpGolmbValue()
{
	UINT_32 bit;
	int nCount;
	UINT_32 val;

	nCount = 0;
	bit = GetData(1);
	while (bit == 0)
	{
		bit = GetData(1);
		nCount++;
	}

	val = ((((int)1) << nCount) - 1) + GetData(nCount);

	return val;
}

INT_32 CBitcalc::GetSignedExpGolmbValue()
{
	INT_32 val;

	val = GetExpGolmbValue();

	if (val == (val/2*2))
	{
		return (-1) * ((val+1)/2);
	}
	else
	{
		return (val+1)/2;
	}
}

void CBitcalc::GetByteData(int len,UINT_8 *pData)
{
	int i;

	for (i=0;i<len;i++)
	{
		pData[i] = (UINT_8)GetData(8);
	}
}

void CBitcalc::SetByteDataAligned(int len, UINT_8 *pData)
{
    int UINT_8Count;

    SetByteAlign();
    UINT_8Count = (m_BitCount / 8);
    memcpy(&m_pData[UINT_8Count],pData,len);
    m_BitCount += len*8;
}