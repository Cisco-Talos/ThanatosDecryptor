# ThanatosDecryptor

ThanatosDecryptor is an executable program that attempts to decrypt certain files encrypted by the Thanatos malware.

File types currently supported include:
+ Image: .gif, .tif, .tiff, .jpg, .jpeg, .png
+ Video: .mpg, .mpeg, .mp4, .avi
+ Audio: .wav
+ Document: .doc, .docx, .xls, .xlsx, .ppt, .pptx, .pdf, .odt, .ods, .odp, .rtf
+ Other: .zip, .7z, .vmdk, .psd, .lnk

In order to decrypt files as quickly as possible, ThanatosDecryptor should be run on the original machine infected with the malware, and against the original .THANATOS files that it created.

ThanatosDecryptor has been tested against versions 1 and 1.1 of the malware.  Known malware sample hashes include:

55aa55229ea26121048b8c5f63a8b6921f134d425fba1eabd754281ca6466b70
97d4145285c80d757229228d13897820d0dc79ab7aa3624f40310098c167ae7e
8df0cb230eeb16ffa70c984ece6b7445a5e2287a55d24e72796e63d96fc5d401
bad7b8d2086ac934c01d3d59af4d70450b0c08a24bc384ec61f40e25b7fbfeb5
02b9e3f24c84fdb8ab67985400056e436b18e5f946549ef534a364dff4a84085
fe1eafb8e31a84c14ad5638d5fd15ab18505efe4f1becaa36eb0c1d75cd1d5a9

## Thanatos Overview

When run, the Thanatos malware looks for files recursively in the following directories:

+ Desktop
+ Documents
+ Downloads
+ Favourites
+ Music
+ OneDrive
+ Pictures
+ Videos

For each file found, the malware derives an encryption key from the number of milliseconds that the infected computer has been running (via a call to [GetTickCount](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724408%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396)), encrypts the file using 256-bit AES encryption, and then discards the encryption key.

It would be practically impossible to brute-force guess the 256-bit AES encryption key directly, but since the malware derives this key from the system uptime (a 32-bit value) the key is effectively 32-bits in length.  On the virtual machine that I tested on, around 100,000 key derivations and AES decryption operations (on one AES block worth of data, needed for decryption success verification) could be performed every second, meaning in the worst case it would take around 12 hours to successfully guess the key *if the system uptime value was random*.  The system uptime is not random, though.  The maximum number of milliseconds you can store in a 32-bit value comes out to be 49.7 days worth, and many people tend to shutdown or hibernate their computers before then (or let them sleep from time to time).  Thus, the system uptime at time of infection is likely to be a fairly low value - starting at 0 and guessing your way up is a decent approach.

A further optimization is enabled by the fact that the system uptime is written to the Windows Event Logs around once per day.  Also, the malware does not modify the .THANATOS file creation dates, so with this information the search space can be reduced to approx. the number of milliseconds within the 24 hours before infection.  At 100k attempts per second, it would take around 14 minutes to guess the key under these conditions.

## ThanatosDecryptor Operation

When run, ThanatosDecryptor first searches the directories listed above for files with the .THANATOS file extension.  Once found, the original file extension (which is preserved by the malware in the file name write before .THANATOS) is compared with the list of file types supported by ThanatosDecryptor.  If the file type is one supported, the file gets queued for decryption.

ThanatosDecryptor also parses the Windows Event Log for the daily uptime messages and uses the encrypted file time metadata to determine a starting value for decryption.  This value is used to derive an encryption key, an AES decryption operation is done against the file contents, and the resulting byte are compared against values known to be at the beginning of those file types.  If the comparison is unsuccessful, increments the seed and tries this process again.  Otherwise, the file is decrypted and written out with the original file name.

Finally, once one file has been successfully encrypted, ThanatosDecryptor uses the SEED value from that decryption attempt as a starting point for decryption attempts against follow-on files (since they are all likely to be very similar).

# Running the Program

Download the latest ThanatosDecryptor.exe file from the Release directory and run it on the infected system as the user that had his/her files encrypted.

# Building

Visual Studios is required for building.  Visual Studio 2017 Community Edition works for me!

To build ThanatosDecryptor from source, clone this repo, cd into the ThanatosDecryptor directory, and from the 'Developer Command Prompt for VS 2017' that ships with Visual Studio 2017, run the following command:

```
msbuild ThanatosDecryptor.vcxproj /p:Configuration=Release /p:Platform=Win32
```

It's easiest to find the Developer Command Prompt using the Windows Start Menu search box.

## Example Output
```
Found the following files able to be decrypted:
C:\Users\zelda\Desktop\testfiles\test.7z.THANATOS
C:\Users\zelda\Desktop\testfiles\Test.doc.THANATOS
C:\Users\zelda\Desktop\testfiles\Test.docx.THANATOS
C:\Users\zelda\Desktop\testfiles\test.gif.lnk.THANATOS
[...]
C:\Users\zelda\Desktop\testfiles\test.xlsx.THANATOS
C:\Users\zelda\Desktop\testfiles\test.zip.THANATOS

Beginning decryption attempt
Attempting to decrypt C:\Users\zelda\Desktop\testfiles\test.7z.THANATOS

Tried 393288 seed values thus far
Successful decryption verification!  Seed: 516031
Successfully wrote decrypted file to: C:\Users\zelda\Desktop\testfiles\test.7z
Attempting to decrypt C:\Users\zelda\Desktop\testfiles\Test.doc.THANATOS
Overriding calculated SEED value for previously successful SEED value (minus 60 secs): 516031

Tried 8257 seed values thus far
Successful decryption verification!  Seed: 516031
Successfully wrote decrypted file to: C:\Users\zelda\Desktop\testfiles\Test.doc
Attempting to decrypt C:\Users\zelda\Desktop\testfiles\Test.docx.THANATOS
Overriding calculated SEED value for previously successful SEED value (minus 60 secs): 516031

Tried 8257 seed values thus far
Successful decryption verification!  Seed: 516031
Successfully wrote decrypted file to: C:\Users\zelda\Desktop\testfiles\Test.docx
Attempting to decrypt C:\Users\zelda\Desktop\testfiles\test.gif.lnk.THANATOS
Overriding calculated SEED value for previously successful SEED value (minus 60 secs): 516031

Tried 8257 seed values thus far
Successful decryption verification!  Seed: 516046
Successfully wrote decrypted file to: C:\Users\zelda\Desktop\testfiles\test.gif.lnk
Attempting to decrypt C:\Users\zelda\Desktop\testfiles\test.gif.THANATOS
Overriding calculated SEED value for previously successful SEED value (minus 60 secs): 516046

[...]

Attempting to decrypt C:\Users\zelda\Desktop\testfiles\test.xlsx.THANATOS
Overriding calculated SEED value for previously successful SEED value (minus 60 secs): 516062

Tried 8226 seed values thus far
Successful decryption verification!  Seed: 8ca3e
Successfully wrote decrypted file to: C:\Users\zelda\Desktop\testfiles\test.xlsx
Attempting to decrypt C:\Users\zelda\Desktop\testfiles\test.zip.THANATOS
Overriding calculated SEED value for previously successful SEED value (minus 60 secs): 516062

Tried 8226 seed values thus far
Successful decryption verification!  Seed: 8ca3e
Successfully wrote decrypted file to: C:\Users\zelda\Desktop\testfiles\test.zip
Press any key to exit
```

Note how some files were encrypted using the same Seed value - according to the GetTickCount man page, the uptime has a resolution of between 10ms and 16ms, which means that it can take between 10-16 ms for another call to GetTickCount to return a different value.

## TODO

This program could be improved in the following ways:
+ Add support for more file types
+ Make the program multi-threaded
+ Add a mode that allows the user to supply the SEED to use for decrypting arbitrary files
+ Using file timestamps we can reconstruct the order in which '.THANATOS' files were created.  This means that for an unsupported file existing between two supported file types that share a Seed value, we can assume that Seed was also used for the unsupported file and decrypt with that (and bypass decryption verification).
