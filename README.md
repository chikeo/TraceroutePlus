# TraceroutePlus
Traceroute utility that offers a diagnostic summary with the slowest hop pinpointed.

Prerequisites
-----------

1 : Windows 8.1 or later Windows OS. This Java application can also be run on Linux. See prerequisite 3 below.

2 : Java SE Development Kit 8u191 Windows x86 package(jdk-8u191-windows-i586.exe) from https://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html

3 : WinPcap version is 4.1.3 (WinPcap_4_1_3.exe) from https://www.winpcap.org/install/default.htm. This Java application can also be run on Linux by substituting WinPcap with libpcap.

4 : Jpcap (JpcapSetup-0.7.exe.zip) from https://sites.google.com/site/sipinspectorsite/download/jpcap.

Working
------

(1) The application requires the target domain to be passed as a commandline argument.

(2) It then lists all the network interfaces on the server, computer or system, and prompts the user to select the interface with the default gateway to use for the trace.
		
(3) The application then begins the traceroute operation, determining and printing the IP addresses and round-trip time to the hops along the way.

(4) It then pinpoints and displays the slowest hop's IP address and its round-trip time.

(5) The application has a test that tests for the existence of one or more network interfaces on the source/host computer system.

Steps to execute
----------------
In the application directory, run the following command and follow the instructions:
java -jar TraceroutePlus.jar "yahoo.com"

