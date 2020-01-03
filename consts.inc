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


 ; Derived from https://github.com/corkami/pocs/blob/master/PE/consts.inc
 ; and https://raw.githubusercontent.com/PELock/Portable-Executable-PE-Format-Poster/master/Portable-Executable-PE-Format-Poster.pdf

struc _IMAGE_DOS_HEADER
    .e_magic      resw 1
    .e_cblp       resw 1
    .e_cp         resw 1
    .e_crlc       resw 1
    .e_cparhdr    resw 1
    .e_minalloc   resw 1
    .e_maxalloc   resw 1
    .e_ss         resw 1
    .e_sp         resw 1
    .e_csum       resw 1
    .e_ip         resw 1
    .e_cs         resw 1
    .e_lfarlc     resw 1
    .e_ovno       resw 1
    .e_res        resw 4
    .e_oemid      resw 1
    .e_oeminfo    resw 1
    .e_res2       resw 10
    .e_lfanew     resd 1
endstruc

IMAGE_SIZEOF_FILE_HEADER equ 20

struc _IMAGE_NT_HEADERS64
    .Signature         resd 1
;   .FileHeader        resb IMAGE_SIZEOF_FILE_HEADER <-- Not really used
;   .OptionalHeader    resb ? <-- Not really used
endstruc

struc _IMAGE_FILE_HEADER
    .Machine              resw 1
    .NumberOfSections     resw 1
    .TimeDateStamp        resd 1
    .PointerToSymbolTable resd 1
    .NumberOfSymbols      resd 1
    .SizeOfOptionalHeader resw 1
    .Characteristics      resw 1
endstruc

IMAGE_NUMBEROF_DIRECTORY_ENTRIES equ 0

struc _IMAGE_OPTIONAL_HEADER64
    .Magic                        resw 1
    .MajorLinkerVersion           resb 1
    .MinorLinkerVersion           resb 1
    .SizeOfCode                   resd 1
    .SizeOfInitializedData        resd 1
    .SizeOfUninitializedData      resd 1
    .AddressOfEntryPoint          resd 1
    .BaseOfCode                   resd 1
    .ImageBase                    resq 1
    .SectionAlignment             resd 1
    .FileAlignment                resd 1
    .MajorOperatingSystemVersion  resw 1
    .MinorOperatingSystemVersion  resw 1
    .MajorImageVersion            resw 1
    .MinorImageVersion            resw 1
    .MajorSubsystemVersion        resw 1
    .MinorSubsystemVersion        resw 1
    .Win32VersionValue            resd 1
    .SizeOfImage                  resd 1
    .SizeOfHeaders                resd 1
    .CheckSum                     resd 1
    .Subsystem                    resw 1
    .DllCharacteristics           resw 1
    .SizeOfStackReserve           resq 1
    .SizeOfStackCommit            resq 1
    .SizeOfHeapReserve            resq 1
    .SizeOfHeapCommit             resq 1
    .LoaderFlags                  resd 1
    .NumberOfRvaAndSizes          resd 1
    .DataDirectory                resq IMAGE_NUMBEROF_DIRECTORY_ENTRIES ; <-- Not used in this PE
endstruc

IMAGE_SIZEOF_SHORT_NAME equ 8

struc _IMAGE_SECTION_HEADER
    .Name                    resb IMAGE_SIZEOF_SHORT_NAME
    .VirtualSize             resd 1 ; Also "PhysicalAddress"
    .VirtualAddress          resd 1
    .SizeOfRawData           resd 1
    .PointerToRawData        resd 1
    .PointerToRelocations    resd 1
    .PointerToLinenumbers    resd 1
    .NumberOfRelocations     resw 1
    .NumberOfLinenumbers     resw 1
    .Characteristics         resd 1
endstruc

IMAGE_SIZEOF_SECTION_HEADER equ 40
