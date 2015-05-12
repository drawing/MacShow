/* send_arp.c 
 * Link with wsock32.lib and iphlpapi.lib 
 */
// gcc send_arp.c -lws2_32 -liphlpapi -o sendarp

#include "send_arp.h"

#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>

int GetMacByARP(char * DestIpString, char * DestMacString)
{
	DWORD dwRetVal = 0;
    IPAddr DestIp = 0;
    IPAddr SrcIp = 0; /* default for src ip */
	ULONG MacAddr[2] = {0}; /* for 6-byte hardware addresses */
    ULONG PhysAddrLen = 6; /* default to length of six bytes */

    char *SrcIpString = NULL;

    BYTE *bPhysAddr;
    int i;

    DestIp = inet_addr(DestIpString);
	
	// printf("Sending ARP request for IP address: %s\n", DestIpString);
	
	PhysAddrLen = sizeof(MacAddr);
	memset(&MacAddr, 0xff, sizeof (MacAddr));
    dwRetVal = SendARP(DestIp, SrcIp, (PULONG)&MacAddr, &PhysAddrLen);
    if (dwRetVal == NO_ERROR) 
	{
        bPhysAddr = (BYTE *) &MacAddr;
        if (PhysAddrLen) 
		{
            for (i = 0; i < (int) PhysAddrLen; i++) 
			{
				sprintf(DestMacString + i*2, "%.2X", (int) bPhysAddr[i]);
            }
        }
		
		return 0;
		/*
		else
		{
            printf("Warning: SendArp completed successfully, but returned length=0\n");
		}
		*/
    } 
	else 
	{
        printf("Error: SendArp failed with error: %d", dwRetVal);
        switch (dwRetVal)
		{
        case ERROR_GEN_FAILURE:
            printf(" (ERROR_GEN_FAILURE)\n");
            break;
        case ERROR_INVALID_PARAMETER:
            printf(" (ERROR_INVALID_PARAMETER)\n");
            break;
        case ERROR_INVALID_USER_BUFFER:
            printf(" (ERROR_INVALID_USER_BUFFER)\n");
            break;
        case ERROR_BAD_NET_NAME:
            printf(" (ERROR_GEN_FAILURE)\n");
            break;
        case ERROR_BUFFER_OVERFLOW:
            printf(" (ERROR_BUFFER_OVERFLOW)\n");
            break;
        case ERROR_NOT_FOUND:
            printf(" (ERROR_NOT_FOUND)\n");
            break;
        default:
            printf("\n");
            break;
        }
		return dwRetVal;
    }
}


