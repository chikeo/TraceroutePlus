/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.chikelueoji.tracerouteplus;
 
 import java.io.IOException;
 import java.net.Inet4Address;
 import java.net.InetAddress;
 import java.net.MalformedURLException;
 import java.net.URL;
 import java.net.UnknownHostException;
import java.util.ArrayList;
 import java.util.Arrays;
import java.util.InputMismatchException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Scanner;
 
 import jpcap.JpcapCaptor;
 import jpcap.JpcapSender;
 import jpcap.NetworkInterface;
 import jpcap.NetworkInterfaceAddress;
 import jpcap.packet.EthernetPacket;
 import jpcap.packet.ICMPPacket;
 import jpcap.packet.IPPacket;
 import jpcap.packet.Packet;
 
 /**
  *  Encapsulates and utilizes the ICMP interface that can be used to trace route remote
  hosts. 
  */
 public class TraceroutePlus implements Runnable
 {
 
     private static final String CONST_SCHEME_HTTP_URL_PREFIX = "http://";
     
     /**
      *  Jpcap <code>NetworkInterface</code> networkInterfaceDevice count. 
      */
     private int deviceCount = 0;
     
     /**
      *  Instance of the Jpcap capturing class
      */
     private JpcapCaptor jpcapCaptor = null;
     
     /**
      *  Instance of the Jpcap network interface used for sending and 
      *  receiving ICMP packets
      */
     private NetworkInterface networkInterfaceDevice = null;
     
     /**
      *  Local IP address
      */
     private InetAddress localIPAddress = null;
     
     /**
      *  Indicates whether to resolve addresses to names or not. By default
      *  disabled, because resolving will slow down trace route presentation.
      */
     private final boolean resolveIPAddressesToHostnames = false;
     
     /**
      *  Host name or IP address to pingPacket
      */
     private String hostName;
     
     /**
      *  Initial TTL (time to live or hop count). When set to 0, thread will do
  trace route.
      */
     private int startingTTLValue;
     
     /**
      *  Instance of the thread that sends ICMP packets
      */
     private Thread workerThread;
     
     /**
      *  Indicates if thread is (or should be) isRunning
      */
     private volatile boolean isRunning = false;
     
     /**
      *  Indicates that thread has been isCompleted
      */
     private volatile boolean isCompleted;
     

     
 
 
     /**
      *  Creates new instance of <code>TraceroutePlus</code>
      */
     public TraceroutePlus()
     {
         this.isRunning       = false;
         this.isCompleted     = true;
         this.workerThread = null;
         
         deviceCount = JpcapCaptor.getDeviceList ().length;
     }
 
         /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // Start the application
        TraceroutePlus traceroutePlus = new TraceroutePlus();
        
        System.out.println("These are the list of Network Interfaces found on this server/computer: ");
        System.out.println();
        
        String[] networkInterfaces = traceroutePlus.getInterfaceList();
        System.out.println();
        
        System.out.println("A total number of network interfaces found were: " + networkInterfaces.length);
        System.out.println();
        
        System.out.print("Please select your Internet Gateway network interface from the above list. Enter its corresponding number: ");
        Scanner commandLineInputScanner = new Scanner(System.in);
        byte networkInterfaceNumber = -1;
        
        try
        { 
            networkInterfaceNumber = commandLineInputScanner.nextByte();
            
        }
        catch(InputMismatchException ime)
        {
            System.out.println("The input type is not an numeric type." + ime);
        }
        catch(NoSuchElementException nse)
        {
            System.out.println("There are no more inputs of the expected type to read." + nse);
        }
        catch(IllegalStateException ise)
        {
            System.out.println("The input scanner is in an illegal state." + ise);
        }
        catch(Exception e)
        {
            System.out.println("An error has occurred." + e);
        }
        
        
        String hostname = "";
        
        try
        {
            if ((args != null) && !args[0].isEmpty())
            {        
                hostname = args[0];
            }
            else
            {
                System.out.println("You must supply the target hostname as an argument to TraceroutePlus.");
                return;
            }
        }
        catch(ArrayIndexOutOfBoundsException aiobe)
        {
            System.out.println("\nYou must supply the target hostname as an argument to TraceroutePlus. \n" + aiobe);
        }
        catch(Exception e)
        {
            System.out.println("\nAn error has occurred. \n" + e);
        }
            // The startingTTLValue must be set to 0 to initiate a traceroute.
            traceroutePlus.startTraceroute(networkInterfaceNumber, args[0].trim(), 0);

    }
     
     /**
      *  Starts thread that will trace route to given host. The instance is 
      *  locked in the mean time, so other trace routes could not start in parallel.
      *  To start trace-route <code>startingTTLValue</code> must be set to 0.
      *  
      *  @param deviceNo    network interface on which to start traceroute
      *  @param hostName    target host address or host name
      *  @param startingTTLValue  initial hop limit (or time-to-live)
      */
     public void startTraceroute( int deviceNo, String hostName, int startingTTLValue )
     {
         synchronized( this )
         {
             if ( ! isCompleted ) {  // Allows only one thread per application run
                 return;
             }
     
             /* Set thread parameters
              */
             openDeviceOnInterface( deviceNo );
             this.hostName   = hostName;
             this.startingTTLValue = startingTTLValue;
 
             /* Enable and disable thread
              */
             isRunning   = true;
             isCompleted = false;
 
             /* Start thread
              */
             workerThread = new Thread( this );
             workerThread.start ();
         }
     }
 
     /**
      *  Stops on-going trace route or pingPacket
      */
     public void cancelTraceroute ()
     {
         synchronized( this )
         {
             isRunning = false; // signal thread to exit
             this.notifyAll (); // interrupt any sleep
         }
         
         System.out.print("Interrupted, cancel the trace route operation");
     }
 
 
     /**
      *  Dumps details about particular Jpcap network interface into log area
      *  
      *  @param title  title line
      *  @param networkInterface     network interface to show 
      */
     public void dumpInterfaceInfo( String title, NetworkInterface networkInterface )
     {
         System.out.println(title);
         System.out.println("    Desc: " + networkInterface.description );
         System.out.println("    Name: " + networkInterface.name );
         for( NetworkInterfaceAddress na : networkInterface.addresses )
         {
             System.out.println( "    Addr: " + na.address );
         }
     }
     
     /**
      *  Gets array of interface descriptions (suitable for the JComboBox)
      *  
      *  @return array of strings with descriptions
      */
     public String[] getInterfaceList ()
     {
         this.deviceCount = JpcapCaptor.getDeviceList ().length;
         String[] networkDevicesList = new String[ this.deviceCount ];
         
         int networkInterfaceIndex = 0;
         for( NetworkInterface networkInterface : JpcapCaptor.getDeviceList () )
         {
             String networkInterfaceDescription = networkInterface.description;
             for( NetworkInterfaceAddress networkInterfaceAddress : networkInterface.addresses )
             {
                 if( networkInterfaceAddress.address instanceof Inet4Address ) {
                     networkInterfaceDescription = networkInterfaceAddress.address.toString () + " --- " + networkInterface.description;
                     break;
                 }
             }
 
             networkDevicesList[ networkInterfaceIndex ] = "interface" + networkInterfaceIndex + " --- " + networkInterfaceDescription;
 
             dumpInterfaceInfo("Interface " + (networkInterfaceIndex++), networkInterface );
         }
         
         return networkDevicesList;
     }
     
     /*
      *  Open Jpcap networkInterfaceDevice to send/receive on particular network interface
      *  
      *  @param deviceNo  networkInterfaceDevice index (e.g., 0, 1..)
      */
     private void openDeviceOnInterface( int deviceNo )
     {
         // Open specified networkInterfaceDevice from the list
         //
         networkInterfaceDevice = JpcapCaptor.getDeviceList()[ deviceNo ];
         localIPAddress = null;
         jpcapCaptor = null;
         
         try
         {
             jpcapCaptor = JpcapCaptor.openDevice(networkInterfaceDevice, 
                     /*MTU*/ 2000, /*promiscuous*/ false, /*timeout*/ 1 );
              
             for( NetworkInterfaceAddress addr : networkInterfaceDevice.addresses )
             {
                 if( addr.address instanceof Inet4Address ) {
                     localIPAddress = addr.address;
                     break;
                 }
             }
         }
         catch ( IOException e )
         {
             networkInterfaceDevice  = null;
             localIPAddress = null;
             jpcapCaptor  = null;
         }
     }
 
     /**
      *  Interruptible sleep (replacement for <code>Thread.sleep</code>).
      *  
      *  @param millis - the length of time to sleep in milliseconds. 
      */
     private void interruptibleSleep( int millis )
     {
         synchronized( this )
         {
             try {
                 this.wait( millis );
             }
             catch( InterruptedException ie ) {
                 isRunning = false; // kills the thread
             }
         }
     }
     
     /**
      *  Obtains MAC address of the default gateway for jpcapCaptor interface.
      *  
      *  @return MAC address as byte array
      */
     private byte[] obtainDefaultGatewayMac( String httpHostToCheck )
     {
         System.out.print("Obtaining the default internet gateway MAC address... ");
         
         byte[] gatewayMAC = null;
         
         if ( jpcapCaptor != null ) try
         {
             InetAddress hostAddr = InetAddress.getByName( httpHostToCheck );
             jpcapCaptor.setFilter( "tcp and dst host " + hostAddr.getHostAddress(), true );
             
             int timeoutTimer = 0;
             new URL(CONST_SCHEME_HTTP_URL_PREFIX + httpHostToCheck ).openStream().close();
             
             while( isRunning )
             {
                 Packet pingPacket = jpcapCaptor.getPacket();
                 
                 if( pingPacket == null )
                 {
                     if ( timeoutTimer < 20 ) { 
                         interruptibleSleep( 100  /*millis*/ );
                         ++timeoutTimer;
                         continue;
                     }
                     /* else: Timeout exceeded
                      */
                     System.out.println("Timeout exceeded.");
                     System.out.println("ERROR: Cannot obtain the MAC address for default internet gateway.");
                     System.out.println("Is there a default gateway on the selected interface?");
                     return gatewayMAC;
                 }
                 
                 byte[] destinationMAC = ((EthernetPacket)pingPacket.datalink).dst_mac; 
                 
                 if( ! Arrays.equals(destinationMAC, networkInterfaceDevice.mac_address ) ) {
                     gatewayMAC = destinationMAC;
                     break;
                 }
 
                 timeoutTimer = 0; // restart timer
                 new URL(CONST_SCHEME_HTTP_URL_PREFIX + httpHostToCheck ).openStream().close();
             }
         }
         catch( MalformedURLException e )
         {
             System.out.println("Invalid URL: " + e.toString ());
         }
         catch( UnknownHostException e )
         {
             System.out.println("Unknown host: " + httpHostToCheck);
         }
         catch( IOException e )
         {
             System.out.println("ERROR: " + e.toString ());
         }
         
         System.out.println(" OK.");
         return gatewayMAC;
     }
    
 
     
     /**
      *  Traces route to given host. The instance is locked during in the mean time
         so other trace routes could not start (isCompleted == false suppresses other 
         threads).
      */
     @Override
     public void run ()
     {
         List<Integer> hopTimeList = new ArrayList<>();
         
         int maxHop = 0;
         
         String slowestHopNode = "";
         
         /* Release instance to other threads
          */
         if ( ! isRunning ) {
             isCompleted = true;
             return;
         }
 
         /* Make sure that capturing networkInterfaceDevice is configured
          */
         if ( jpcapCaptor == null ) {
             System.out.println("Capture network interface device is not configured...");
             isRunning   = false;
             isCompleted = true;
             return;
         }
 
         /* Starts sending ICMP packets and tracing route...
          */
         try
         {

             System.out.println("------------------------------------------------------------------------------------------------------------");
             System.out.println();
             System.out.print("Tracing route to " + hostName + "...");
             
             InetAddress remoteIP = InetAddress.getByName( hostName );
             
             System.out.println("  [" + remoteIP.getHostAddress () + "]");
 
             byte[] defaultGatewayMAC = obtainDefaultGatewayMac( "yahoo.com" );
             if ( defaultGatewayMAC == null )
             {
                 isRunning = false;
                 isCompleted = true;
                 return;
             }
   
             if ( startingTTLValue == 0 ) {
                 System.out.println("Tracing route to " + remoteIP + "...");
             }
             
             /* Create ICMP packet
              */
             ICMPPacket icmp = new ICMPPacket ();
 
             icmp.type       = ICMPPacket.ICMP_ECHO;
             icmp.seq        = 100;
             icmp.id         = 0;
             icmp.data       = "data".getBytes ();
             
             icmp.setIPv4Parameter(0,          // int priority - Priority
                     false,      // boolean: IP flag bit: Delay
                     false,      // boolean: IP flag bit: Through
                     false,      // boolean: IP flag bit: Reliability
                     0,          // int: Type of Service (TOS)
                     false,      // boolean: Fragmentation Reservation flag
                     false,      // boolean: Don't fragment flag
                     false,      // boolean: More fragment flag
                     0,          // int: Offset
                     0,          // int: Identifier
                     0,          // int: Time To Live
                     IPPacket.IPPROTO_ICMP, // Protocol 
                     localIPAddress,    // Source IP address
                     remoteIP    // Destination IP address
                     );
 
             EthernetPacket ether = new EthernetPacket ();
             ether.frametype = EthernetPacket.ETHERTYPE_IP;
             ether.src_mac   = networkInterfaceDevice.mac_address;
             ether.dst_mac   = defaultGatewayMAC;
             icmp.datalink   = ether;
 
             /* Send ICMP packets...
              */
             JpcapSender sender = jpcapCaptor.getJpcapSenderInstance ();
             jpcapCaptor.setFilter("icmp and dst host " + localIPAddress.getHostAddress(), true );
             
             icmp.hop_limit  = (short)startingTTLValue;
             System.out.print(icmp.hop_limit + ": ");
             int timeoutTimer = 0;
             int timeoutCounter = 0;
             long tStart = System.nanoTime ();
             sender.sendPacket( icmp );
             
             while( isRunning )
             {
                 ICMPPacket p = (ICMPPacket)jpcapCaptor.getPacket ();
                 int tDelay = (int)( ( System.nanoTime () - tStart ) / 1000000l );
 
                 if( p == null ) // TIMEOUT
                 {
                     /* Wait until some time elapses
                      */
                     if ( timeoutTimer < 30 ) 
                     {
                         interruptibleSleep( timeoutTimer < 10 ? 1 : 100 );
                         ++timeoutTimer;

                         continue;
                     }
 
                     /* Increase timeout counter and either retry or advance Hop limit
                      */
                     ++timeoutCounter;
                     System.out.println(" * (Timeout) " + timeoutCounter);
                     
                     if ( timeoutCounter < 3 ) // Retry send to the same Hop
                     {
                         System.out.print(icmp.hop_limit + ": ");
                         tStart = System.nanoTime ();
                         timeoutTimer = 0;
                         sender.sendPacket( icmp );
                     }
                     else // Advance Hop limit and send to next hop
                     {
                         ++icmp.hop_limit;
                         System.out.print(icmp.hop_limit + ": ");
                         timeoutTimer = 0;
                         timeoutCounter = 0;
                         tStart = System.nanoTime ();
                         sender.sendPacket( icmp );
                     }
                     continue;
                 }
                 
                 /* We are here because we got some ICMP packet... resolve name first.
                  */
                 String hopID = p.src_ip.getHostAddress ();
                 if (resolveIPAddressesToHostnames) {
                     p.src_ip.getHostName();
                     hopID = p.src_ip.toString();
                 }
 
                 /* Now, in case if we received 'time exceeded' packet we should advance
                  * to the next Hop limit. Otherwise if host is either unreachable or 
                  * we got echo reply, we should quit.
                  */
                 switch(p.type)
                 {
                     case ICMPPacket.ICMP_TIMXCEED: // Time exceeded
                         System.out.println(hopID + ", " + tDelay + " ms");
                        if(icmp.hop_limit > 1)
                        {
                           hopTimeList.add(tDelay);

                           if (hopTimeList.size() > 0)
                           {
                               int output = hopTimeList.get(hopTimeList.size()-1).compareTo(maxHop);
                               if (output > 0)
                               {
                                   maxHop = hopTimeList.get(hopTimeList.size()-1);
                                   slowestHopNode = hopID;
                               }
                           }

                        }
                        ++icmp.hop_limit;
                        System.out.print(icmp.hop_limit + ": ");
                        timeoutTimer = 0;
                        timeoutCounter = 0;
                        tStart = System.nanoTime ();
                        sender.sendPacket( icmp );
                     break;
                     
                     case ICMPPacket.ICMP_UNREACH: // Host unreachable
                        System.out.println(hopID + " unreachable");
                        isRunning = false;
                     break;
                     
                     case ICMPPacket.ICMP_ECHOREPLY: // Echo reply from target
                        System.out.println(hopID + ", " + tDelay + " ms");
                        isRunning = false;
                     break;
                 }

             }
             
             System.out.println();
             System.out.println("The slowest hop node is: " + slowestHopNode + " with a RTTL of " + maxHop + " ms.\n");
         }
         catch( UnknownHostException e )
         {
             System.out.println("Unknown host: " + hostName);
             isCompleted = true;
             return;
         }
         catch( IOException e )
         {
             System.out.println("ERROR: " + e.toString ());
             isCompleted = true;
             return;
         }
 
         /* Release instance to other threads
          */
         if(startingTTLValue == 0)
         {
            System.out.println("TraceroutePlus completed.\n");
         }
         isCompleted = true;
      }
 }