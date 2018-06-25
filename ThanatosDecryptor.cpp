/*
 * Copyright 2018, Cisco Systems, Inc. (Talos)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// ThanatosDecrypter.cpp : Contains the logic to attempt brute-force
// decryption of files encrypted by the Thanatos malware family

//#include "stdafx.h"
#include <windows.h>
#include <lmcons.h>
#include <wincrypt.h>
#include <stdio.h>

// Set DEBUG to 1 to enable some more verbose log messages
#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#define DEBUG_CWPRINTF _cwprintf
#define DEBUG_PRINTF printf
#else
#define DEBUG_CWPRINTF(fmt, ...)
#define DEBUG_PRINTF(fmt, ...)
#endif

#define AES_BLOCK_SIZE 16
#define MAX_MAGIC_EXT_LEN (64*sizeof(WCHAR))
#define MAX_MAGIC_BYTES_LEN AES_BLOCK_SIZE

// Struct to hold the file magic values used for decryption verification
typedef struct _magic_entry {
    const WCHAR *ext; // Must be < MAX_MAGIC_EXT_LEN bytes in length
    BYTE bytes[MAX_MAGIC_BYTES_LEN];
    BYTE mask[MAX_MAGIC_BYTES_LEN];
    unsigned int len;
} magic_entry_t;

// From: https://en.wikipedia.org/wiki/List_of_file_signatures
magic_entry_t gMagic[] = {
    { L".gif",{ 0x47, 0x49, 0x46, 0x38 },{ 0xFF, 0xFF, 0xFF, 0xFF }, 4 },

    { L".tif",{ 0x49, 0x49, 0x00, 0x00 },{ 0xFB, 0xFB, 0xD5, 0xD5 }, 4 },
    { L".tiff",{ 0x49, 0x49, 0x00, 0x00 },{ 0xFB, 0xFB, 0xD5, 0xD5 }, 4 },
    
    { L".jpg",{ 0xFF, 0xD8, 0xFF, 0xC0 },{ 0xFF, 0xFF, 0xFF, 0xC0 }, 4 },
    { L".jpeg",{ 0xFF, 0xD8, 0xFF, 0xC0 },{ 0xFF, 0xFF, 0xFF, 0xC0 }, 4 },
    
    { L".zip",{ 0x50, 0x4B, 0x01, 0x00 },{ 0xFF, 0xFF, 0xF9, 0xF1 }, 4 },
    { L".odt",{ 0x50, 0x4B, 0x01, 0x00 },{ 0xFF, 0xFF, 0xF9, 0xF1 }, 4 },
    { L".ods",{ 0x50, 0x4B, 0x01, 0x00 },{ 0xFF, 0xFF, 0xF9, 0xF1 }, 4 },
    { L".odp",{ 0x50, 0x4B, 0x01, 0x00 },{ 0xFF, 0xFF, 0xF9, 0xF1 }, 4 },
    { L".docx",{ 0x50, 0x4B, 0x01, 0x00 },{ 0xFF, 0xFF, 0xF9, 0xF1 }, 4 },
    { L".xlsx",{ 0x50, 0x4B, 0x01, 0x00 },{ 0xFF, 0xFF, 0xF9, 0xF1 }, 4 },
    { L".pptx",{ 0x50, 0x4B, 0x01, 0x00 },{ 0xFF, 0xFF, 0xF9, 0xF1 }, 4 },
    
    { L".png",{ 0x89, 0x50, 0x4E, 0x47 },{ 0xFF, 0xFF, 0xFF, 0xFF }, 4 },
    
    { L".pdf",{ 0x25, 0x50, 0x44, 0x46 },{ 0xFF, 0xFF, 0xFF, 0xFF }, 4 },
    
    // TODO I don't have a good way to create a PSD file for testing
    // at the moment, so hopefully this just works!
    { L".psd",{ 0x38, 0x42, 0x50, 0x53 },{ 0xFF, 0xFF, 0xFF, 0xFF }, 4 },
    
    { L".wav",{ 0x52, 0x49, 0x46, 0x46 },{ 0xFF, 0xFF, 0xFF, 0xFF }, 4 },

    // TODO Create an avi file for testing
    { L".avi",{ 0x52, 0x49, 0x46, 0x46 },{ 0xFF, 0xFF, 0xFF, 0xFF }, 4 },
    
    // TODO There might be a lot of false positives with this one
    //{ L".mp3",{ 0xFF, 0xFB },{ 0xFF, 0xFF }, 2 },

    // TODO We need a signature that encompasses both - otherwise decrypting
    // an MP3 that is of the other type will take a long time and not
    // successfully decrypt
    //{ L".mp3",{ 0x49, 0x44, 0x33 },{ 0xFF, 0xFF, 0xFF }, 3 },
    
    { L".doc",{ 0xD0, 0xCF, 0x11, 0xE0 },{ 0xFF, 0xFF, 0xFF, 0xFF }, 4 },
    { L".xls",{ 0xD0, 0xCF, 0x11, 0xE0 },{ 0xFF, 0xFF, 0xFF, 0xFF }, 4 },
    { L".ppt",{ 0xD0, 0xCF, 0x11, 0xE0 },{ 0xFF, 0xFF, 0xFF, 0xFF }, 4 },
    
    { L".vmdk",{ 0x4B, 0x44, 0x4D },{ 0xFF, 0xFF, 0xFF }, 3 },
    
    { L".rtf",{ 0x7B, 0x5C, 0x72, 0x74 },{ 0xFF, 0xFF, 0xFF, 0xFF }, 4 },
    
    { L".7z",{ 0x37, 0x7A, 0xBC, 0xAF },{ 0xFF, 0xFF, 0xFF, 0xFF }, 4 },
    
    { L".mpg",{ 0x00, 0x00, 0x01, 0xB2 },{ 0xFF, 0xFF, 0xFF, 0xF6 }, 4 },
    { L".mpeg",{ 0x00, 0x00, 0x01, 0xB2 },{ 0xFF, 0xFF, 0xFF, 0xF6 }, 4 },
    
    // https://www.forensicswiki.org/wiki/LNK
    { L".lnk",{ 0x4C, 0x00, 0x00, 0x00 },{ 0xFF, 0xFF, 0xFF, 0xFF }, 4 },

    // https://stackoverflow.com/a/13190041/9457431
    { L".mp4",{ 0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79},{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, 7 },
};

// We'll save off the restart times that we observe
// This time is measured in the number of seconds elapsed since
// 00:00:00 January 1, 1970, Universal Coordinated Time
DWORD gRestartTimes[1024];
unsigned int gRestartTimesLen = 0;

// Struct used to store the uptime message details from the event log
typedef struct _uptime_notification {
    DWORD notificationTime;
    DWORD uptime; // In seconds - I'm assuming this follows the GetTickCount output (wraps after 47 days?) TODO
} uptime_notification_t;

uptime_notification_t gUptimeNotifications[1024];
unsigned int gUptimeNotificationsLen = 0;

const WCHAR gThanatosExt[] = L".THANATOS";

// Struct used to store the details about the encrypted files
typedef struct _encrypted_file {
    struct _encrypted_file *next;
    WCHAR *path;
    UINT64 creationTime;
    BYTE *fileData;
    DWORD fileDataLen;
    DWORD seed; // uptime seed value to start decrypting at
    unsigned int magicIndex; // index into the magic array based on filetype
    BOOL succeeded; // Set after decryption succeeds for this file

} encrypted_file_t;

encrypted_file_t *gEncryptedFilesListHead = NULL;

// Helper function from: https://stackoverflow.com/a/6161842/9457431
#define WINDOWS_TICK_IN_SECS 10000000
#define SEC_TO_UNIX_EPOCH 11644473600LL
static inline DWORD WindowsTickToUnixSeconds(UINT64 windowsTicks)
{
    return (DWORD)(windowsTicks / WINDOWS_TICK_IN_SECS - SEC_TO_UNIX_EPOCH);
}

// Function to recreate the steps that the Thanatos malware uses to
// generate an encryption key from a given seed value (system uptime)
static BOOL getKeyForSeed(HCRYPTPROV hProv, DWORD seed, HCRYPTKEY *hKey)
{
    BOOL result = TRUE;
    HCRYPTHASH hHash = NULL;

    srand(seed);

    char password[21] = { 0 };

    // Generate a password from the seed.  A password is a 20 character string of
    // numbers.  For instance: 70654614798392963697
    for (int i = 0; i < 20; i++)
    {
        snprintf(password, _countof(password), "%s%d", password, rand() % 10);
    }

    /*
    8B 55 F4                                     mov     edx, [ebp+phProv]
    8D 4D F8                                     lea     ecx, [ebp+phHash]
    51                                           push    ecx             ; phHash
    53                                           push    ebx             ; dwFlags
    53                                           push    ebx             ; hKey
    68 0C 80 00 00                               push    800Ch           ; Algid
    52                                           push    edx             ; hProv
    FF 15 18 B0 D3 00                            call    ds:CryptCreateHash
    */

    // CALG_SHA_256 0x0000800c

    if (FALSE == CryptCreateHash(hProv, CALG_SHA_256, NULL, 0, &hHash))
    {
        printf("Call to CryptCreateHash failed with error 0x%lx\n", GetLastError());
        result = FALSE;
        goto CLEANUP;
    }

    /*
    53                                           push    ebx             ; dwFlags
    2B C2                                        sub     eax, edx        ; compute key strlen (== 20)
    50                                           push    eax             ; dwDataLen
    8B 45 F8                                     mov     eax, [ebp+phHash]
    56                                           push    esi             ; pbData (20 character key)
    50                                           push    eax             ; hHash
    FF 15 0C B0 D3 00                            call    ds:CryptHashData
    */

    if (FALSE == CryptHashData(hHash, (const BYTE *)password, (DWORD)strlen(password), 0))
    {
        printf("Call to CryptHashData failed with error 0x%lx\n", GetLastError());
        result = FALSE;
        goto CLEANUP;
    }

    /*
    8B 55 F8                                     mov     edx, [ebp+phHash]
    8B 45 F4                                     mov     eax, [ebp+phProv]
    8D 4D FC                                     lea     ecx, [ebp+phKey]
    51                                           push    ecx             ; phKey
    6A 01                                        push    1               ; dwFlags
    52                                           push    edx             ; hBaseData
    68 10 66 00 00                               push    6610h           ; Algid
    50                                           push    eax             ; hProv
    FF 15 28 B0 D3 00                            call    ds:CryptDeriveKey
    */

    // CALG_AES_256 0x00006610
    // #define CRYPT_EXPORTABLE 1

    if (FALSE == CryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE, hKey))
    {
        printf("Call to CryptDeriveKey failed with error 0x%lx\n", GetLastError());
        result = FALSE;
        goto CLEANUP;
    }

CLEANUP:
    if (hHash != NULL)
    {
        CryptDestroyHash(hHash);
    }

    return result;
}

// Compare the specified number of decrypted file bytes with the
// magic byte values (with byte masking)
static BOOL ValidateFileDecryption(BYTE *fileData, unsigned int fileDataLen, unsigned int magicIndex)
{
    if (fileDataLen < gMagic[magicIndex].len)
    {
        return FALSE;
    }

    unsigned int i = 0;
    for (; i < gMagic[magicIndex].len; i++)
    {
        if ((fileData[i] & gMagic[magicIndex].mask[i]) != (gMagic[magicIndex].bytes[i] & gMagic[magicIndex].mask[i]))
        {
            break;
        }
    }

    if (i == gMagic[magicIndex].len)
    {
        return TRUE;
    }

    return FALSE;
}

// Determine whether decryption verification magic exists for this file type,
// and if so, write out the index into the list of magic
static BOOL DecryptionVerificationExists(WCHAR *fileName, unsigned int *magicIndex)
{
    WCHAR search[MAX_MAGIC_EXT_LEN + sizeof(gThanatosExt)];

    for (unsigned int i = 0; i < (sizeof(gMagic) / sizeof(gMagic[0])); i++)
    {
        _snwprintf_s(search, _countof(search), L"%s%s", gMagic[i].ext, gThanatosExt);

        // Do a case insensitive search for the substring at the end of the path
        if (0 != _wcsicmp(fileName + wcslen(fileName) - wcslen(search), search))
        {
            continue;
        }

        // Found a corresponding magic entry!
        *magicIndex = i;
        return TRUE;
    }

    return FALSE;
}

// Determine the best starting seed based on the file time and the metadata
// gleaned from the system event log.
static void setBestStartingSeed(encrypted_file_t *entry)
{
    // Find the restart time closest and < the file creation time.
    // NOTE: This should be the same for all files on a given 
    // infected system, but we'll just compute for each file.

    DWORD priorBootTime = 0;
    DWORD priorUptime = 0;
    DWORD creationTimeSecs = WindowsTickToUnixSeconds(entry->creationTime);

    for (unsigned int i = 0; i < gRestartTimesLen; i++)
    {
        if (gRestartTimes[i] < creationTimeSecs)
        {
            priorBootTime = gRestartTimes[i];
            break;
        }
    }

    if (0 == priorBootTime)
    {
        printf("Unable to detect any system boot event log messages... Continuing\n");

        // We'll continue on, but this probably means something is messed up with event log parsing
    }

    // Now, get the uptime value > bestRebootTime and < fileTime
    // These messages seem to happen sporadicly

    for (unsigned int i = 0; i < gUptimeNotificationsLen; i++)
    {
        if (gUptimeNotifications[i].notificationTime <= creationTimeSecs &&
            gUptimeNotifications[i].notificationTime >= priorBootTime)
        {
            priorUptime = gUptimeNotifications[i].uptime;
            break;
        }
    }

    entry->seed = priorUptime * 1000;

    return;
}

// Recursively search for files with the .THANATOS file extension that
// we have decryptoin magic for
// NOTE: pathSize should be the number of chars in pathBuf, not the
// number of bytes (since pathBuf is of type WCHAR *)
static BOOL searchForFilesToDecrypt(WCHAR *pathBuf, size_t pathSize)
{
    bool result = TRUE;

    // Save the length so we can use it to restore the path later
    size_t pathLen = wcslen(pathBuf);

    _snwprintf_s(pathBuf, pathSize, pathLen + 2, L"%s\\*", pathBuf);

    DEBUG_CWPRINTF(L"\nSearching for files in: %s\n", pathBuf);

    WIN32_FIND_DATA fileMetaData;

    HANDLE handle = FindFirstFile(pathBuf, &fileMetaData);

    while (INVALID_HANDLE_VALUE != handle)
    {
        ULARGE_INTEGER creationTime;
        ULARGE_INTEGER fileSize;
        encrypted_file_t *entry = NULL;

        creationTime.LowPart = fileMetaData.ftCreationTime.dwLowDateTime;
        creationTime.HighPart = fileMetaData.ftCreationTime.dwHighDateTime;

        fileSize.LowPart = fileMetaData.nFileSizeLow;
        fileSize.HighPart = fileMetaData.nFileSizeHigh;

        // Restore pathBuf to it's original length
        pathBuf[pathLen] = L'\0';

        // And set it to now equal the full file/directory path
        _snwprintf_s(pathBuf, pathSize, pathLen + 1 + wcslen(fileMetaData.cFileName), L"%s\\%s", pathBuf, fileMetaData.cFileName);

        // See if it's a directory and if so, recurse
        if (fileMetaData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (0 != wcsncmp(fileMetaData.cFileName, L".", 2) &&
                0 != wcsncmp(fileMetaData.cFileName, L"..", 3))
            {
                if (FALSE == searchForFilesToDecrypt(pathBuf, pathSize))
                {
                    result = FALSE;
                    goto CLEANUP;
                }
            }

            goto SKIP_TO_NEXT_FILE;
        }

        // Make sure there are at least MAX_MAGIC_BYTES_LEN bytes so we can do the
        // decryption success verification
        if (fileSize.QuadPart < MAX_MAGIC_BYTES_LEN)
        {
            goto SKIP_TO_NEXT_FILE;
        }

        // See whether decrypt verification exists for this file type.  We'll cache
        // the index of the gMagic struct corresponding to this filetype for the
        // decryption verification done later
        unsigned int magicIndex;
        if (DecryptionVerificationExists(fileMetaData.cFileName, &magicIndex))
        {
            wprintf(L"\n%s\\%s:\n    Known file-type. Will attempt to decrypt...\n", pathBuf, fileMetaData.cFileName);
        }
        else
        {
            wprintf(L"\n%s\\%s:\n     File type not currently supported for decryption. Skipping...\n", pathBuf, fileMetaData.cFileName);
            goto SKIP_TO_NEXT_FILE;
        }

        // Found a .THANATOS file that we have magic for!

        // Allocate space for the metadata struct and file path together
        entry = (encrypted_file_t *)_aligned_malloc(sizeof(encrypted_file_t) + ((wcslen(pathBuf) + 1) * sizeof(WCHAR)), 32);

        if (NULL == entry)
        {
            printf("Out of memory\n");
            result = FALSE;
            goto CLEANUP;
        }

        entry->next = NULL;
        entry->path = (WCHAR *)(((BYTE *)entry) + sizeof(*entry));
        entry->creationTime = creationTime.QuadPart;
        entry->fileData = NULL; // We'll read the file contents in later
        entry->fileDataLen = (DWORD)fileSize.QuadPart; // Assuming no file > 4 GB this cast should be fine
        entry->succeeded = FALSE;
        entry->magicIndex = magicIndex;

        // Try to make a good guess as to what the starting seed should be
        setBestStartingSeed(entry);

        printf("    Will attempt to decrypt file starting with seed: %lu\n", entry->seed);

        wcscpy_s(entry->path, wcslen(pathBuf) + 1, pathBuf);

        if (NULL == gEncryptedFilesListHead)
        {
            gEncryptedFilesListHead = entry;
        }
        else
        {
            encrypted_file_t *ptr;
            for (ptr = gEncryptedFilesListHead; ptr->next != NULL; ptr = ptr->next);

            ptr->next = entry;
        }

    SKIP_TO_NEXT_FILE:

        if (0 == FindNextFile(handle, &fileMetaData))
        {
            FindClose(handle);
            handle = INVALID_HANDLE_VALUE;
            break;
        }
    }

CLEANUP:

    if (INVALID_HANDLE_VALUE != handle)
    {
        FindClose(handle);
    }

    return result;
}

// Search through the event log for indicators of reboot and historic uptimes
static BOOL getEventLogInfo()
{
    HANDLE hEventLog = OpenEventLog(NULL, L"System");

    DWORD NumberOfRecords;

    if (FALSE == GetNumberOfEventLogRecords(hEventLog, &NumberOfRecords))
    {
        printf("Unable to get the number of 'System' EventLog Records\n");
        return FALSE;
    }

    DEBUG_PRINTF("%lu System EventLog records reported\n", NumberOfRecords);

    for (DWORD i = 0; i < NumberOfRecords; )
    {
        BYTE buffer[0x7ffff];
        DWORD bytesRead;
        DWORD minBytesNeeded;

        if (FALSE == ReadEventLog(hEventLog, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ, 0, &buffer, sizeof(buffer), &bytesRead, &minBytesNeeded))
        {
            if (ERROR_HANDLE_EOF != GetLastError())
            {
                printf("Error when reading EventLog: 0x%lx\n", GetLastError());
                return FALSE;
            }
        }

        if (bytesRead < sizeof(EVENTLOGRECORD))
        {
            printf("Error when reading EventLog (not enough data returned)\n");
            return FALSE;
        }

        BYTE *ptr = buffer;

        while (ptr <= (buffer + bytesRead - sizeof(EVENTLOGRECORD)))
        {
            EVENTLOGRECORD *record = (EVENTLOGRECORD *)ptr;

            if (record->EventID == 0x80001775)
            {
                // We found an 'Event log service was started' message, which is a decent place
                // to start for determining the OS start time
                // https://social.technet.microsoft.com/Forums/ie/en-US/e47bc3a4-50d9-4ad8-aae0-2209098e4e71/how-to-get-last-10-reboot-times-of-a-computer?forum=winserverpowershell
                DEBUG_PRINTF("Found boot time indicator: %lx\n", record->TimeGenerated);

                if (gRestartTimesLen < (sizeof(gRestartTimes) / sizeof(gRestartTimes[0])))
                {
                    gRestartTimes[gRestartTimesLen++] = record->TimeGenerated;
                }
            }

            if (record->EventID == 0x8000177D)
            {
                // We found an 'The system uptime is 265464 seconds' message, which is the
                // best way I've found to determine the system uptime.
                DEBUG_PRINTF("Found system uptime message: %lx\n", record->TimeGenerated);

                if (gUptimeNotificationsLen < (sizeof(gUptimeNotifications) / sizeof(gUptimeNotifications[0])))
                {
                    gUptimeNotifications[gUptimeNotificationsLen].notificationTime = record->TimeGenerated;

                    /*
                    Here's what the record looks like on my machine... The uptime is stored as a WCHAR
                    string with 8 bytes from the indicated StringOffset (which is 0x70 in the case
                    of the record below).

                    TODO Is this consistent across locales / versions of Windows?

                    0000  30 02 00 00 4c 66 4c 65 d1 08 00 00 d6 ee 0a 5b  0...LfLe.......[
                    0010  d6 ee 0a 5b 7d 17 00 80 04 00 07 00 00 00 00 00  ...[}...........
                    0020  00 00 00 00 70 00 00 00 00 00 00 00 70 00 00 00  ....p.......p...
                    0030  6a 01 00 00 be 00 00 00 45 00 76 00 65 00 6e 00  j.......E.v.e.n.
                    0040  74 00 4c 00 6f 00 67 00 00 00 44 00 45 00 53 00  t.L.o.g...D.E.S.
                    0050  4b 00 54 00 4f 00 50 00 2d 00 31 00 34 00 53 00  K.T.O.P.-.1.4.S.
                    0060  4b 00 51 00 4f 00 49 00 00 00 00 00 00 00 00 00  K.Q.O.I.........
                    0070  00 00 00 00 00 00 00 00 31 00 33 00 31 00 35 00  ........1.3.1.5.
                    0080  35 00 00 00 36 00 30 00 00 00 33 00 30 00 30 00  5...6.0...3.0.0.
                    0090  20 00 45 00 61 00 73 00 74 00 65 00 72 00 6e 00   .E.a.s.t.e.r.n.
                    00a0  20 00 53 00 74 00 61 00 6e 00 64 00 61 00 72 00   .S.t.a.n.d.a.r.
                    00b0  64 00 20 00 54 00 69 00 6d 00 65 00 00 00 31 00  d. .T.i.m.e...1.
                    00c0  2e 00 31 00 00 00 30 00 00 00 57 00 69 00 6e 00  ..1...0...W.i.n.
                    00d0  64 00 6f 00 77 00 73 00 20 00 31 00 30 00 20 00  d.o.w.s. .1.0. .
                    00e0  45 00 6e 00 74 00 65 00 72 00 70 00 72 00 69 00  E.n.t.e.r.p.r.i.
                    00f0  73 00 65 00 00 00 31 00 30 00 2e 00 30 00 2e 00  s.e...1.0...0...
                    ...
                    */
                    DWORD uptime = _wtoi((WCHAR *)(((BYTE *)record) + (record->StringOffset + 4 * sizeof(WCHAR))));
                    gUptimeNotifications[gUptimeNotificationsLen++].uptime = uptime;

                    if (0 == uptime)
                    {
                        printf("Warning, extracted '0' from uptime notification... Parsing error? Continuing...\n");
                    }
                }
            }

            i++;
            ptr = ptr + record->Length;
        }
    }

    return TRUE;
}

int main()
{
    int result = EXIT_SUCCESS;

    // Look through the event log for approx. times when the system booted
    if (FALSE == getEventLogInfo())
    {
        result = EXIT_FAILURE;
        goto WAIT_FOR_USER_AND_EXIT;
    }

    {
        // Search for THANATOS files
        WCHAR username[UNLEN + 1];
        DWORD usernameLen = UNLEN + 1;
        GetUserName(username, &usernameLen);

        const WCHAR *subdirs[] = {
            L"\\Desktop",
            L"\\Documents",
            L"\\Downloads",
            L"\\Favourites",
            L"\\Music",
            L"\\OneDrive",
            L"\\Pictures",
            L"\\Videos",
        };

        for (int i = 0; i < (sizeof(subdirs) / sizeof(subdirs[0])); i++)
        {
            WCHAR path[0x8000];

            _snwprintf_s(path, _countof(path), L"C:\\Users\\%s%s", username, subdirs[i]);

            // Recurse down, searching for files and trying to decrypt them
            if (FALSE == searchForFilesToDecrypt(path, _countof(path)))
            {
                result = EXIT_FAILURE;
                goto WAIT_FOR_USER_AND_EXIT;
            }
        }
    }

    if (NULL == gEncryptedFilesListHead)
    {
        printf("Unable to find any files that can be decrypted with this tool\n");
    }
    else
    {
        printf("\nFound the following files able to be decrypted:\n");

        for (encrypted_file_t *ptr = gEncryptedFilesListHead; ptr != NULL; ptr = ptr->next)
        {
            wprintf(L"%s\n", ptr->path);
        }

        printf("\nBeginning decryption attempt\n");

        // Initialize global crypt context
        /*
        68 00 00 00 F0                               push    0F0000000h; dwFlags
        33 DB                                        xor     ebx, ebx
        6A 18                                        push    18h; dwProvType
        53                                           push    ebx; szProvider
        53                                           push    ebx; szContainer
        8D 45 F4                                     lea     eax, [ebp + phProv]
        50                                           push    eax; phProv
        89 5D F4                                     mov     [ebp+phProv], ebx
        89 5D FC                                     mov     [ebp+phKey], ebx
        89 5D F8                                     mov     [ebp+phHash], ebx
        FF 15 20 B0 D3 00                            call    ds : CryptAcquireContextA
        */

        // #define CRYPT_VERIFYCONTEXT 0xF0000000
        // #define PROV_RSA_AES      24

        HCRYPTPROV hProv = NULL;
        HANDLE hInFile = INVALID_HANDLE_VALUE;
        HANDLE hOutFile = INVALID_HANDLE_VALUE;
        HCRYPTKEY hKey = NULL;

        if (FALSE == CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        {
            printf("CryptAcquireContext failed with error 0x%lx\n", GetLastError());
            result = EXIT_FAILURE;
            goto DECRYPTION_ATTEMPT_CLEANUP;
        }

        for (encrypted_file_t *ptr = gEncryptedFilesListHead; ptr != NULL; ptr = ptr->next)
        {
            wprintf(L"Attempting to decrypt %s\n", ptr->path);

            // Open the file

            hInFile = CreateFile(ptr->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

            if (INVALID_HANDLE_VALUE == hInFile)
            {
                wprintf(L"Unable to open file: %s (0x%lx)\n", ptr->path, GetLastError());
                continue;
            }

            // Malloc space for it's contents
            ptr->fileData = (BYTE *)malloc(ptr->fileDataLen);

            if (NULL == ptr->fileData)
            {
                wprintf(L"Unable to malloc enough space for file contents: %s\n", ptr->path);
                result = EXIT_FAILURE;
                goto DECRYPTION_ATTEMPT_CLEANUP;
            }

            DWORD bytesRead = 0;
            for (unsigned int i = 0; i < ptr->fileDataLen; i += bytesRead)
            {
                if (FALSE == ReadFile(hInFile, ptr->fileData + i, ptr->fileDataLen - i, &bytesRead, NULL))
                {
                    // TODO Should this be fatal?
                    printf("Error when reading file: 0x%lx\n", GetLastError());
                    result = EXIT_FAILURE;
                    goto DECRYPTION_ATTEMPT_CLEANUP;
                }
            }

            // If a previous decrypt was successful, start from that seed instead.
            // The files in the list are likely to be in the same order as the
            // malware saw them, which means the seeds used will be very close and
            // increasing.
            DWORD previousSuccessfulSeed = 0;
            for (encrypted_file_t *ptr2 = gEncryptedFilesListHead; ptr2 != ptr; ptr2 = ptr2->next)
            {
                if (TRUE == ptr2->succeeded)
                {
                    previousSuccessfulSeed = ptr2->seed;
                }
            }

            if (0 != previousSuccessfulSeed)
            {
                // Just in case, subtract 60 seconds
                ptr->seed = previousSuccessfulSeed > 60000 ? previousSuccessfulSeed - 60000 : 0;
                printf("Overriding calculated SEED value for previously successful SEED value (minus 60 secs): %lu\n", ptr->seed);
            }

            printf("\n");
            for (DWORD i = ptr->seed; i != (ptr->seed - 1); i++)
            {
                if (0 == (i % 65536))
                {
                    printf("\rTried %lu seed values thus far", (i > ptr->seed ? i - ptr->seed : i + ptr->seed));
                    fflush(stdout);
                }

                if (FALSE == getKeyForSeed(hProv, i, &hKey))
                {
                    // TODO Error
                    // TODO Should this be fatal?
                    printf("A failure occurred when attempting to get a key for the given seed\n");
                    result = EXIT_FAILURE;
                    goto DECRYPTION_ATTEMPT_CLEANUP;
                }

                /*
                This is the encryption routine - do the compliment

                FF 15 94 B0 D3 00                            call    ds:HeapAlloc
                8B F0                                        mov     esi, eax
                85 F6                                        test    esi, esi
                74 4E                                        jz      short loc_D21160

                8B 4D F0                                     mov     ecx, [ebp+var_10]
                8B 55 08                                     mov     edx, [ebp+arg_0]
                8B 02                                        mov     eax, [edx]
                51                                           push    ecx             ; size_t
                50                                           push    eax             ; void *
                56                                           push    esi             ; void *
                E8 5E C2 00 00                               call    _memcpy_0
                8B 4D 0C                                     mov     ecx, [ebp+pdwDataLen]
                8B 45 FC                                     mov     eax, [ebp+phKey]
                83 C4 0C                                     add     esp, 0Ch
                51                                           push    ecx             ; dwBufLen
                8D 55 F0                                     lea     edx, [ebp+var_10]
                52                                           push    edx             ; pdwDataLen
                56                                           push    esi             ; pbData
                6A 00                                        push    0               ; dwFlags
                6A 01                                        push    1               ; Final
                6A 00                                        push    0               ; hHash
                50                                           push    eax             ; hKey
                FF D3                                        call    ebx ; CryptEncrypt
                85 C0                                        test    eax, eax
                74 22                                        jz      short loc_D21160
                */

                BYTE firstBytes[MAX_MAGIC_BYTES_LEN];
                DWORD firstBytesLen = sizeof(firstBytes);

                // We verified that there are at least MAX_MAGIC_BYTES_LEN bytes before
                // adding it into the list of files to decrypt, so no need to check here.
                memcpy(firstBytes, ptr->fileData, firstBytesLen);

                if (FALSE == CryptDecrypt(hKey, NULL, FALSE, 0, firstBytes, &firstBytesLen))
                {
                    wprintf(L"\nError decrypting file: %s 0x%lx\n", ptr->path, GetLastError());
                    result = EXIT_FAILURE;
                    goto DECRYPTION_ATTEMPT_CLEANUP;
                }

                if (FALSE == ValidateFileDecryption(firstBytes, firstBytesLen, ptr->magicIndex))
                {
                    goto TRY_NEXT_SEED;
                }
                else
                {
                    printf("\nSuccessful decryption verification!  Seed: %lu\n", i);

                    // Copy the bytes that we already decrypted
                    memcpy(ptr->fileData, firstBytes, firstBytesLen);

                    // NOTE: This works because I'm assuming firstBytesLen
                    // won't change with a call to CryptDecrypt when 'final'
                    // is not True

                    DWORD bytesToDecrypt = ptr->fileDataLen - firstBytesLen;

                    // Decrypt the file

                    if (FALSE == CryptDecrypt(hKey, NULL, TRUE, 0, ptr->fileData + firstBytesLen, &(bytesToDecrypt)))
                    {
                        wprintf(L"Error decrypting file: %s 0x%lx\n", ptr->path, GetLastError());
                        result = EXIT_FAILURE;
                        goto DECRYPTION_ATTEMPT_CLEANUP;
                    }

                    ptr->fileDataLen = firstBytesLen + bytesToDecrypt;
                    ptr->seed = i;
                    ptr->succeeded = TRUE;

                    // Write the file out.  As a shortcut, just modify the existing path var
                    // as the new output file name.

                    (ptr->path)[wcslen(ptr->path) - wcslen(gThanatosExt)] = L'\0';

                    hOutFile = CreateFile(ptr->path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

                    // TODO Do this check earlier
                    if (INVALID_HANDLE_VALUE == hOutFile)
                    {
                        wprintf(L"Unable to create new file with decrypted contents (a file with this name may already exist): %s\n", ptr->path);
                        CryptDestroyKey(hKey);
                        break;
                    }

                    DWORD bytesWritten = 0;
                    for (unsigned int j = 0; j < ptr->fileDataLen; j += bytesWritten)
                    {
                        if (FALSE == WriteFile(hOutFile, ptr->fileData + j, ptr->fileDataLen - j, &bytesWritten, NULL))
                        {
                            // TODO Should this be fatal?
                            printf("Error when writing output file 0x%lx\n", GetLastError());
                            result = EXIT_FAILURE;
                            goto DECRYPTION_ATTEMPT_CLEANUP;
                        }
                    }

                    wprintf(L"Successfully wrote decrypted file to: %s\n", ptr->path);

                    CloseHandle(hOutFile);
                    CryptDestroyKey(hKey);
                    break;
                }

            TRY_NEXT_SEED:
                if (NULL != hKey)
                {
                    CryptDestroyKey(hKey);
                }
            }

            DEBUG_PRINTF("Moving on to the next file\n");

            // Free the file data so we don't use too much memory
            free(ptr->fileData);
            ptr->fileData = NULL;

            // Close the encrypted file
            CloseHandle(hInFile);
        }

    DECRYPTION_ATTEMPT_CLEANUP:
        // Release the crypt context
        if (NULL != hProv)
        {
            CryptReleaseContext(hProv, 0);
        }

        if (INVALID_HANDLE_VALUE != hInFile)
        {
            CloseHandle(hInFile);
        }

        if (INVALID_HANDLE_VALUE != hOutFile)
        {
            CloseHandle(hOutFile);
        }

        if (NULL != hKey)
        {
            CryptDestroyKey(hKey);
        }

        for (encrypted_file_t *ptr = gEncryptedFilesListHead; ptr != NULL;)
        {
            encrypted_file_t *tmp = ptr->next;

            if (ptr->fileData != NULL)
            {
                free(ptr->fileData);
            }

            // ptr->name is allocated with ptr, so this cleans up both
            _aligned_free(ptr);

            ptr = tmp;
        }
    }

WAIT_FOR_USER_AND_EXIT:
    printf("Press any key to exit\n");
    getchar();

    return result;
}
