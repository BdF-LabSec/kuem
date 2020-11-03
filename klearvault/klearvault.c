/*	Benjamin DELPY `gentilkiwi`
	LabSec - DGSI DIT ARCOS
	benjamin.delpy@banque-france.fr / benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include <stdio.h>
#include <windows.h>
#include <wincred.h>

int wmain(void)
{
	int ret;
	DWORD credCount, deletedCount = 0, i, err;
	PCREDENTIAL* pCredential = NULL;

	if (CredEnumerate(L"AppSense_DataNow_*", 0, &credCount, &pCredential))
	{
		if (pCredential)
		{
			for (i = 0; i < credCount; i++)
			{
				if (pCredential[i]->TargetName)
				{
					wprintf(L"%s -- CredDelete: ", pCredential[i]->TargetName);
					if (CredDelete(pCredential[i]->TargetName, pCredential[i]->Type, 0))
					{
						wprintf(L"DELETED\n");
						deletedCount++;
					}
					else wprintf(L"%u (0x%08x)\n", GetLastError(), GetLastError());
				}
			}
			CredFree(pCredential);
		}
		
		ret = ((credCount << 16) & 0xffff0000) | (deletedCount & 0x0000ffff);
	}
	else
	{
		err = GetLastError();
		if (err == ERROR_NOT_FOUND)
		{
			ret = -2;
			wprintf(L"No matching credential found\n");
		}
		else
		{
			ret = -1;
			wprintf(L"CredEnumerate: %u (0x%08x)\n", err, err);
		}
	}
	
	wprintf(L"\n> Will return: %i (%08x)", ret, ret);
	return ret;
}