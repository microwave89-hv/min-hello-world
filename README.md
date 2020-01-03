Only tested on this https://github.com/microwave89-hv/hw-fw-notes/blob/master/hw HW!
Not tested with emulators such as QEMU or VBox!

# THE COMMAND "MAKE INSTALL" IS GOING TO OVERWRITE ANY EXISTING $(MNTDIR)/EFI/BOOT/BOOTX64.EFI! THIS MIGHT RENDER YOUR OS UNBOOTABLE! ONLY INSTALL IF YOU'RE 100% SURE YOU KNOW WHAT YOU DO!

This is an attempt on a rather freestanding Hello World. It does not require refit, refind, or EfiShell. The assembled file is its own "boot loader". That's why the file should be at $(MNTDIR)/EFI/BOOT/BOOTX64.EFI. This entry point is always valid according to EFI 1.10 Spec by Intel(R).

Moreover does it not depend upon overly complex gnu-efi or EDK makefiles, or cryptic command lines.

No library sources, or bins, or other dependencies needed altogether :) 

Built on MacOS X High Sierra using nasm 2.14+