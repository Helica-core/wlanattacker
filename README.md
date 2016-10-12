#WlanAtt@cker ver:0.3
	对目标主机执行arp欺骗，达到禁止上网，中间人攻击的目的。

#使用
	运行WF.exe
	某些情况下需要管理员权限才能获得网卡信息
	
	指令：
	wlan-scan:scanning the wlan to collect the information of computer at wlan
	ip-forbidden: ip-forbidden <add (target ip)>|<start|stop>
	mid-attack: mid-attack <start|stop> listen the packet between A and B
	add-target: add-target <A||B(target set)> <(target ip)>
	
	详见使用指南（coming soon...

#编译
	windows:	
		解压后，在目录下执行BUILD.bat
	Linux:
		coming soon...

#更新地址
	http://github.com/helica-core/wlanattacker
	
#TO-DO List
	1.自动获取本机MAC,ip地址
	2.目标列表清空
	3.中间人攻击的消息转发
	4.变量函数规范命名
	...



#联系作者
	www.github.com/helica-core

