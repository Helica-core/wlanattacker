#
# gengrate WF.exe
# use gcc

MAKE 	= make.exe -r 

default:	
	$(MAKE) exe

WF.exe: WF_main.c common_func.c WF_include.h packet_callback.c arp_spoofing.c
	gcc WF_main.c -I ./WpdPack/Include  -L ./WpdPack/Lib -lwpcap -lWSock32 -o WF 

exe: 
	$(MAKE) WF.exe

run	:
	@$(MAKE) WF.exe
	@echo ====================================
	@./WF.exe
