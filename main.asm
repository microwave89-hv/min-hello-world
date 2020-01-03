 ; Copyright (c) 2019 microwave89-hv
 ;
 ; Licensed under the Apache License, Version 2.0 (the "License");
 ; you may not use this file except in compliance with the License.
 ; You may obtain a copy of the License at
 ;
 ;      http://www.apache.org/licenses/LICENSE-2.0
 ;
 ; Unless required by applicable law or agreed to in writing, software
 ; distributed under the License is distributed on an "AS IS" BASIS,
 ; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ; See the License for the specific language governing permissions and
 ; limitations under the License.


 ; derived from https://raw.githubusercontent.com/charlesap/nasm-uefi/master/yo.asm
 ; and the compiled and linked output of hello-world2.c.

%include "consts.inc"
BITS 64

; DOS signature not needed by Apple EFI implementation. This correllates to behavior of PeCoffLoader.c & co. in EDK 1.10.
IMAGE_NT_SIGNATURE 						equ 0x4550    ; 'PE\0\0'

IMAGE_NT_HEADERS64:
istruc _IMAGE_NT_HEADERS64
    at _IMAGE_NT_HEADERS64.Signature,				dd IMAGE_NT_SIGNATURE ; MUST but could be 'VZ' too for Terse image. Header would be quite different then.
iend

IMAGE_FILE_MACHINE_AMD64 					equ 0x8664
IMAGE_FILE_EXECUTABLE_IMAGE					equ (1 << 1)
IMAGE_FILE_LARGE_ADDRESS_AWARE					equ (1 << 5)

IMAGE_FILE_HEADER:
istruc _IMAGE_FILE_HEADER
    at _IMAGE_FILE_HEADER.Machine, 				dw IMAGE_FILE_MACHINE_AMD64 ; MUST
    at _IMAGE_FILE_HEADER.NumberOfSections, 			dw 2 ; MUST
    at _IMAGE_FILE_HEADER.TimeDateStamp,       			dd 0
    at _IMAGE_FILE_HEADER.PointerToSymbolTable, 		dd 0
    at _IMAGE_FILE_HEADER.NumberOfSymbols,      		dd 0
    at _IMAGE_FILE_HEADER.SizeOfOptionalHeader, 		dw 0x70 ; MUST
    at _IMAGE_FILE_HEADER.Characteristics, 			dw 0 ; IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE ; 0x22 ; not needed
iend

IMAGE_NT_OPTIONAL_HDR64_MAGIC 					equ 0x20b
IMAGE_SUBSYSTEM_EFI_APPLICATION 				equ 0xa

IMAGE_OPTIONAL_HEADER64:
istruc _IMAGE_OPTIONAL_HEADER64
    at _IMAGE_OPTIONAL_HEADER64.Magic,				dw IMAGE_NT_OPTIONAL_HDR64_MAGIC ; MUST
    at _IMAGE_OPTIONAL_HEADER64.MajorLinkerVersion,		db 0
    at _IMAGE_OPTIONAL_HEADER64.MinorLinkerVersion,		db 0
    at _IMAGE_OPTIONAL_HEADER64.SizeOfCode,			dd 0
    at _IMAGE_OPTIONAL_HEADER64.SizeOfInitializedData,		dd 0
    at _IMAGE_OPTIONAL_HEADER64.SizeOfUninitializedData,	dd 0
    at _IMAGE_OPTIONAL_HEADER64.AddressOfEntryPoint,		dd 0x1000 ; MUST
    at _IMAGE_OPTIONAL_HEADER64.BaseOfCode,			dd 0
    at _IMAGE_OPTIONAL_HEADER64.ImageBase,			dq 0x100000000 ; MUST?
    at _IMAGE_OPTIONAL_HEADER64.SectionAlignment,		dd 0x1000 ; MUST?
    at _IMAGE_OPTIONAL_HEADER64.FileAlignment,			dd 0 ; 0x200
    at _IMAGE_OPTIONAL_HEADER64.MajorOperatingSystemVersion,	dw 0
    at _IMAGE_OPTIONAL_HEADER64.MinorOperatingSystemVersion,	dw 0
    at _IMAGE_OPTIONAL_HEADER64.MajorImageVersion,		dw 0
    at _IMAGE_OPTIONAL_HEADER64.MinorImageVersion,		dw 0
    at _IMAGE_OPTIONAL_HEADER64.MajorSubsystemVersion,		dw 0
    at _IMAGE_OPTIONAL_HEADER64.MinorSubsystemVersion,		dw 0
    at _IMAGE_OPTIONAL_HEADER64.Win32VersionValue,		dd 0
    at _IMAGE_OPTIONAL_HEADER64.SizeOfImage,			dd 0x3000 ; MUST
    at _IMAGE_OPTIONAL_HEADER64.SizeOfHeaders,			dd 0x400 ; MUST
    at _IMAGE_OPTIONAL_HEADER64.CheckSum,			dd 0
    at _IMAGE_OPTIONAL_HEADER64.Subsystem,			dw IMAGE_SUBSYSTEM_EFI_APPLICATION ; MUST
    at _IMAGE_OPTIONAL_HEADER64.DllCharacteristics,		dw 0
    at _IMAGE_OPTIONAL_HEADER64.SizeOfStackReserve,		dq 0 ; 0x100000
    at _IMAGE_OPTIONAL_HEADER64.SizeOfStackCommit,		dq 0 ; 0x1000
    at _IMAGE_OPTIONAL_HEADER64.SizeOfHeapReserve,		dq 0 ; 0x100000
    at _IMAGE_OPTIONAL_HEADER64.SizeOfHeapCommit,		dq 0 ; 0x1000
    at _IMAGE_OPTIONAL_HEADER64.LoaderFlags,			dd 0
    at _IMAGE_OPTIONAL_HEADER64.NumberOfRvaAndSizes,		dd IMAGE_NUMBEROF_DIRECTORY_ENTRIES
    ; at _IMAGE_OPTIONAL_HEADER64.DataDirectory,			times IMAGE_NUMBEROF_DIRECTORY_ENTRIES dq 0
iend

IMAGE_SCN_CNT_CODE						equ (1 << 5)
IMAGE_SCN_CNT_INITIALIZED_DATA					equ (1 << 6)
IMAGE_SCN_MEM_EXECUTE						equ (1 << 29)
IMAGE_SCN_MEM_READ						equ (1 << 30)

SECTION_HEADER1:
istruc _IMAGE_SECTION_HEADER
    at _IMAGE_SECTION_HEADER.Name,				db '.text',0,0,0
    at _IMAGE_SECTION_HEADER.VirtualSize,			dd 0 ; Also called "PhysicalAddress" 
    at _IMAGE_SECTION_HEADER.VirtualAddress,			dd 0x1000 ; MUST
    at _IMAGE_SECTION_HEADER.SizeOfRawData,			dd 0x200 ; MUST
    at _IMAGE_SECTION_HEADER.PointerToRawData,			dd 0x400 ; MUST
    at _IMAGE_SECTION_HEADER.PointerToRelocations,		dd 0
    at _IMAGE_SECTION_HEADER.PointerToLinenumbers,		dd 0
    at _IMAGE_SECTION_HEADER.NumberOfRelocations,		dw 0
    at _IMAGE_SECTION_HEADER.NumberOfLinenumbers,		dw 0
    at _IMAGE_SECTION_HEADER.Characteristics,			dd 0 ; IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ ; not needed
iend

SECTION_HEADER2:
istruc _IMAGE_SECTION_HEADER
    at _IMAGE_SECTION_HEADER.Name,				db '.data',0,0,0
    at _IMAGE_SECTION_HEADER.VirtualSize,			dd 0 ; Also called "PhysicalAddress"
    at _IMAGE_SECTION_HEADER.VirtualAddress,			dd 0x2000 ; MUST
    at _IMAGE_SECTION_HEADER.SizeOfRawData,			dd 0x200 ; MUST
    at _IMAGE_SECTION_HEADER.PointerToRawData,			dd 0x600 ; MUST
    at _IMAGE_SECTION_HEADER.PointerToRelocations,		dd 0
    at _IMAGE_SECTION_HEADER.PointerToLinenumbers,		dd 0
    at _IMAGE_SECTION_HEADER.NumberOfRelocations,		dw 0
    at _IMAGE_SECTION_HEADER.NumberOfLinenumbers,		dw 0
    at _IMAGE_SECTION_HEADER.Characteristics,			dd 0 ; IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ ; not needed
iend

times 0x400 - ($-$$)						db 0          ; Align next section at 512 bytes boundary
push rbx ; Callers consider rbx to be non-volatile according to MSFT x64 convention.
sub rsp, 0x30 ; 32 bytes shadow space + EFI_CONSOLE_CONTROL_PROTOCOL* pConsoleControlInterface; + fix aligning broken by push
mov rbx, rdx
mov rcx, [rbx + 0x58] ; EFI_RUNTIME_SERVICES* pRuntimeServices = pEfiSystemTable->pRuntimeServices;
mov rax, [rbx + 0x60] ; EFI_BOOT_SERVICES* pBootServices = pEfiSystemTable->pBootServices;
lea rcx, [rel gEfiConsoleControlProtocolGuid - 0x200 + 0x1000]
xor edx, edx
lea r8, [rsp + 0x28] ; &pConsoleControlInterface
call [rax + 0x140]; pBootServices->fpLocateProtocol(&gEfiConsoleControlProtocolGuid, NULL, &pConsoleControlInterface); ; Non-standard protocol, which must be located first.
test rax, rax
jne fail
xor edx, edx
mov rcx, [rsp + 0x28] ; *&pConsoleControlInterface
call [rcx + 8] ; pConsoleControlInterface->fpSetMode(pConsoleControlInterface, EfiConsoleControlScreenText); ; With MacBook Pro's, BOOTX64.EFI's are loaded when graphics is on.
test rax, rax
jne fail
mov rcx, [rbx + 0x40] ; SIMPLE_TEXT_OUTPUT_INTERFACE* con_out = pEfiSystemTable->pConOut;
lea rdx, [rel myvar - 0x200 + 0x1000] ; myvar - raw_code_size + (virtual_data_address - virtual_code_address)
call [rcx + 8] ; Only now printed text will be visible!
jmp infloop ; "Prevent" deleting the text so it can be read by humans...when done reset platform by pressing Cmd+Option+Shift+Power.

fail:
xor ecx, ecx
mov rdx, rcx
mov r8, rcx
mov r9, rcx
shl ecx, 1 ; EfiResetShutdown
jmp [rax + 0x68] ; no_return fpResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL); ; In case the machine turns off as opposed to hanging this code must have been executed.
infloop:
jmp infloop
add rsp, 0x30 ; never reachable...
pop rbx
ret



times 0x600 - ($-$$)						int3          ; Align next section at 512 bytes boundary

myvar dw __utf16__('h3l10 W0rld?'), 0xd, 0xa, 0 ; In the EFI realm, which has been
                                                    ; heavily influenced by the Microsoft
                                                    ; world, wide chars are required to
                                                    ; have 2 bytes, as opposed to 4 bytes
                                                    ; on *nixes.
                                                    ; Moreover both carriage return and
                                                    ; line feed are required for a new line.
gEfiConsoleControlProtocolGuid dd 0xf42f7782
			       dw 0x12e,
			       dw 0x4c12,
			       db 0x99, 0x56, 0x49, 0xf9, 0x43, 0x4, 0xf7, 0x21
times 0x800 - ($-$$)						db 0