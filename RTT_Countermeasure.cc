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

void ReceivePacket(Ptr<const Packet> p, const Address& addr, Ptr<RttEstimator> rttEstimator)
{
    Time receivedTime = Simulator::Now();
    // This is a simplification. In a real scenario, you would track when packets are sent.
    Time sentTime = Simulator::Now(); // This should actually be tracked properly
    rttEstimator->Measurement(receivedTime - sentTime);

    std::cout << receivedTime.GetSeconds() << "\t" << p->GetSize() << "\tRTT: " << rttEstimator->GetEstimate().GetSeconds() << "s\n";
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

    YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default();
    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    wifiPhy.SetChannel(wifiChannel.Create());
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::TwoRayGroundPropagationLossModel", "SystemLoss", DoubleValue(1), "HeightAboveZ", DoubleValue(1.5));

    // For range near 250m
    wifiPhy.Set("TxPowerStart", DoubleValue(30));
    wifiPhy.Set("TxPowerEnd", DoubleValue(30));

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

    // Position the nodes accordingly
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        positionAlloc->Add(Vector(i * 100.0, 0, 0)); // 100m apart
    }
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    // RTT Estimators for each node
    std::vector<Ptr<RttEstimator>> rttEstimators;
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        Ptr<RttEstimator> estimator = CreateObject<RttMeanDeviation>();
        rttEstimators.push_back(estimator);
    }

    // Create applications and bind the receive callback with RTT estimator
    uint16_t port = 9;  // UDP port for echo application
    UdpEchoServerHelper echoServer(port);
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        ApplicationContainer serverApp = echoServer.Install(nodes.Get(i));
        serverApp.Start(Seconds(1.0));
        serverApp.Stop(Seconds(100.0));

        Ptr<Socket> recvSocket = Socket::CreateSocket(nodes.Get(i), UdpSocketFactory::GetTypeId());
        recvSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), port));
        recvSocket->SetRecvCallback(MakeBoundCallback(&ReceivePacket, rttEstimators[i]));
    }

    // Normal traffic simulation setup continues...
    // Further code for setting up clients, wormhole, flow monitors etc.

    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
