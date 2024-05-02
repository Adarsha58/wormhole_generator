#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("WormholeExample");

void ReceivePacket(Ptr<const Packet> p, const Address & addr)
{
    std::cout << Simulator::Now ().GetSeconds () << "\t" << p->GetSize() << "\n";
}

int main(int argc, char *argv[])
{
    bool enableFlowMonitor = true;
    bool enableWormhole = true;
    std::string phyMode("DsssRate1Mbps");

    CommandLine cmd;
    cmd.AddValue("EnableMonitor", "Enable Flow Monitor", enableFlowMonitor);
    cmd.AddValue("phyMode", "Wifi Phy mode", phyMode);
    cmd.AddValue("EnableWormhole", "Enable Wormhole", enableWormhole);
    cmd.Parse(argc, argv);

    NodeContainer nodes;
    nodes.Create(18);

    // Set up WiFi
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211g);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode", StringValue(phyMode), "ControlMode", StringValue(phyMode));


    YansWifiPhyHelper wifiPhy = YansWifiPhyHelper();
    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    wifiPhy.SetChannel(wifiChannel.Create());
    wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss ("ns3::TwoRayGroundPropagationLossModel",
                                "SystemLoss", DoubleValue(1),
                                "HeightAboveZ", DoubleValue(1.5));



    // For range near 250m
    wifiPhy.Set ("TxPowerStart", DoubleValue(30));
    wifiPhy.Set ("TxPowerEnd", DoubleValue(30));

   
    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");


    NetDeviceContainer devices = wifi.Install(wifiPhy, wifiMac, nodes);
    wifiPhy.EnablePcap("wifi", devices);  // Enable PCAP for WiFi devices
    

    

    // Enable AODV
    AodvHelper aodv;
    InternetStackHelper stack;
    stack.SetRoutingHelper(aodv);
    stack.Install(nodes);

    // Assign IP addresses
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // Position the nodes accoridingly
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        positionAlloc->Add(Vector(i * 100.0, 0, 0)); // 100m apart
    }
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);



    Ipv4InterfaceContainer mal_ipcont;
    // Introduce wormhole on the end point
    if (enableWormhole)
    {
        NodeContainer wormholeNodes1(nodes.Get(0), nodes.Get(5));  // Create wormhole between node 1 and 6
        NodeContainer wormholeNodes2(nodes.Get(2), nodes.Get(8));
        NodeContainer wormholeNodes3(nodes.Get(7), nodes.Get(10));
        NodeContainer wormholeNodes4(nodes.Get(11), nodes.Get(16));
        NetDeviceContainer mal_devices = wifi.Install(wifiPhy, wifiMac, wormholeNodes);

        // Assign IP addresses
        address.SetBase("10.1.2.0", "255.255.255.0");
        Ipv4InterfaceContainer interfaces = address.Assign(devices);
        mal_ipcont = address.Assign(mal_devices);



        AodvHelper malicious_aodv; 
        malicious_aodv.Set("EnableWrmAttack",BooleanValue(true));
        malicious_aodv.Set("FirstWifiEndOfWormTunnel",Ipv4AddressValue("10.0.2.1"));
        malicious_aodv.Set("SecondWifiEndOfWormTunnel",Ipv4AddressValue("10.0.2.2"));

        
        stack.SetRoutingHelper(malicious_aodv);
        stack.Install(wormholeNodes);          
    }

    // Install applications: UDP echo server and client

    uint16_t echoPort = 9;

    // Install UDP echo server on the second last node (node 5)
    UdpEchoServerHelper echoServer(echoPort);
    ApplicationContainer serverApps = echoServer.Install(nodes.Get(4)); // Install on the second last node
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(100.0));

    // Install UDP echo client on the second node (node 1)
    UdpEchoClientHelper echoClient(interfaces.GetAddress(4), echoPort); // Using the IP address of the second last node
    echoClient.SetAttribute("MaxPackets", UintegerValue(1)); // Sending a total of 20 packets
    echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0))); // Interval between packets
    echoClient.SetAttribute("PacketSize", UintegerValue(1024)); // Size of each packet

    ApplicationContainer clientApps = echoClient.Install(nodes.Get(1)); // Install on the second node
    clientApps.Start(Seconds(2.0));
    clientApps.Stop(Seconds(100.0));



    // Flow Monitor
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(Seconds(100.0));

    if (enableFlowMonitor)
    {
        monitor->SerializeToXmlFile("WormholeFlowMonitor.xml", true, true);
    }


    Simulator::Run();
    Simulator::Destroy();

    // Print per flow statistics
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin(); i != stats.end(); ++i)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        std::cout << "Flow " << i->first << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
        std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
        std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
        std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds()) / 1024 / 1024 << " Mbps\n";
    }

    return 0;
}
