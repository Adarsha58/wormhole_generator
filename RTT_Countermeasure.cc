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
#include "rtt-estimator.h"  // Include the RTT Estimator header

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("WormholeExample");

class RttLogger
{
public:
    RttLogger() : m_rttEstimator(CreateObject<RttMeanDeviation>())
    {
        m_rttEstimator->Measurement(Seconds(0.1)); 
    }

    void SentPacket(Ptr<Socket> socket, uint32_t bytes)
    {
        Time now = Simulator::Now(); 
        m_sendTimes[socket->GetNode()->GetId()] = now;
        NS_LOG_INFO("Packet sent at " << now.GetSeconds());
    }

    void ReceivedPacket(Ptr<Socket> socket, Ptr<const Packet> packet, const Address& from)
    {
        Time now = Simulator::Now(); 
        auto sentTimeIt = m_sendTimes.find(socket->GetNode()->GetId());
        if (sentTimeIt != m_sendTimes.end())
        {
            Time rtt = now - sentTimeIt->second;
            m_rttEstimator->Measurement(rtt); 
            NS_LOG_INFO("Received packet at " << now.GetSeconds() << " with RTT: " << rtt.GetSeconds());
        }
    }

private:
    std::map<uint32_t, Time> m_sendTimes; 
    Ptr<RttEstimator> m_rttEstimator; 

void ReceivePacket(Ptr<const Packet> p, const Address& addr)
{
    std::cout << Simulator::Now().GetSeconds() << "\t" << p->GetSize() << "\n";
}

int main(int argc, char* argv[])
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
    nodes.Create(6);

    // Set up WiFi
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211g);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode", StringValue(phyMode), "ControlMode", StringValue(phyMode));

    YansWifiPhyHelper wifiPhy = YansWifiPhyHelper();
    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    wifiPhy.SetChannel(wifiChannel.Create());
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::TwoRayGroundPropagationLossModel",
        "SystemLoss", DoubleValue(1),
        "HeightAboveZ", DoubleValue(1.5));

    wifiPhy.Set("TxPowerStart", DoubleValue(30));
    wifiPhy.Set("TxPowerEnd", DoubleValue(30));

    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer devices = wifi.Install(wifiPhy, wifiMac, nodes);
    wifiPhy.EnablePcap("wifi", devices);

    // Enable AODV
    AodvHelper aodv;
    InternetStackHelper stack;
    stack.SetRoutingHelper(aodv);
    stack.Install(nodes);

    // Assign IP addresses
    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // Position the nodes
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        positionAlloc->Add(Vector(i * 100.0, 0, 0)); // 100m apart
    }
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    Ipv4InterfaceContainer mal_ipcont;
    // Introduce wormhole if enabled
    if (enableWormhole)
    {
        NodeContainer wormholeNodes(nodes.Get(0), nodes.Get(5));  // Create wormhole between node 0 and 5
        NetDeviceContainer mal_devices = wifi.Install(wifiPhy, wifiMac, wormholeNodes);

        address.SetBase("10.1.2.0", "255.255.255.0");
        mal_ipcont = address.Assign(mal_devices);

        AodvHelper malicious_aodv;
        malicious_aodv.Set("EnableWrmAttack", BooleanValue(true));
        malicious_aodv.Set("FirstWifiEndOfWormTunnel", Ipv4AddressValue("10.0.2.1"));
        malicious_aodv.Set("SecondWifiEndOfWormTunnel", Ipv4AddressValue("10.0.2.2"));

        stack.SetRoutingHelper(malicious_aodv);
        stack.Install(wormholeNodes);
    }

    // Install applications: UDP echo server and client with RTT monitoring
    RttLogger rttLogger; // RTT logger

    uint16_t echoPort = 9;
    UdpEchoServerHelper echoServer(echoPort);
    ApplicationContainer serverApps = echoServer.Install(nodes.Get(4)); // Server on node 4
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(100.0));

    Ptr<Socket> ns3UdpSocket = Socket::CreateSocket(nodes.Get(1), UdpSocketFactory::GetTypeId());
    ns3UdpSocket->SetRecvCallback(MakeCallback(&RttLogger::ReceivedPacket, &rttLogger));
    ns3UdpSocket->SetSendCallback(MakeCallback(&RttLogger::SentPacket, &rttLogger));

    UdpEchoClientHelper echoClient(interfaces.GetAddress(4), echoPort);
    echoClient.SetAttribute("MaxPackets", UintegerValue(1));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    echoClient.SetAttribute("PacketSize", UintegerValue(1024));

    ApplicationContainer clientApps = echoClient.Install(nodes.Get(1)); // Client on node 1
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
