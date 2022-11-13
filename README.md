# FileExplorer
Custom C/C++ File Explorer
## Notes
GUI is built using MFC classes \
Files management uses ntdll/syscalls functions directly \
Application works exclusively with its own disk (VHDx) which has to be mounted previously \
Allows drag and drop from any filesystem \
For now, only allowed file operation is deletion and viewing filesystem information (FAT32) \
Files and folder icon images are stored in custom file called $shell. File is stored in the root partition and loaded at runtime using AVL tree algorithm for management.
## TODO 
Attach kernel-mode driver (filter) to application volume and perform all encryption operations on the fly from driver \
Display file virtual & physical memory
## Motivation
Understanding Windows filesystem kernel technologies (especially cache manager)
## Mount process
![alt text](https://github.com/alexvogt91/FileExplorer/blob/main/src/1.PNG?raw=true)
#
![alt text](https://github.com/alexvogt91/FileExplorer/blob/main/src/2.PNG?raw=true)
#
![alt text](https://github.com/alexvogt91/FileExplorer/blob/main/src/3.PNG?raw=true)
#
![alt text](https://github.com/alexvogt91/FileExplorer/blob/main/src/Capture2.PNG?raw=true)
#
![alt text](https://github.com/alexvogt91/FileExplorer/blob/main/src/Capture.PNG?raw=true)
