#include <string>
#include <fstream>
#include <stdlib>
#include "ns3/packet-sink.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/traffic-control-module.h"
#include "ns3/netanim-module.h"
#include "ns3/point-to-point-layout-module.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("Latency");

int main(int argc,char* argv[]){

    uint32_t nSpokes = 12;
    bool DqnEnable = false;

    CommandLine cmd;
    cmd.AddValue("nSpoke","Number of nodes to place in the star",nSpokes);
    cmd.AddValue("DqnEnable","Enable the Dqn QueueDisc",DqnEnable);
    cmd.Parse(argc,argv);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("10Mbps"));
    p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));
    PointToPointStarHelper star(nSpokes,p2p);

    InternetStackHelper internet;
    star.InstallStack (internet);

    TrafficControlHelper tchmy;
    if(DqnEnable){
        tchmy.SetRootQueueDisc("ns3::DqnQueueDisc");
    }else{
        tchmy.SetRootQueueDisc("ns3::AfqQueueDisc");
    }
    tchmy.Install(star.GetHub()->GetDevice(star.SpokeCount() - 1));

    star.AssignIpv4Addresses(Ipv4AddressHelper("10.1.1.0","255.255.255.0"));

    uint16_t udpPort = 50000;
    Address udpSinkLocalAddress(InetSocketAddress(Ipv4Address::GetAny(),udpPort));
    PacketSinkHelper udpSinkHelper("ns3::UdpSocketFactory",udpSinkLocalAddress);
    ApplicationContainer udpSinkApp = udpSinkHelper.Install(star.GetSpokeNode(star.SpokeCount() - 1));
    udpSinkApp.Start(Seconds(0.0));
    udpSinkApp.Stop(Seconds(100.0));

    uint16_t tcpPort = 50001;
    Address tcpSinkLocalAddress(InetSocketAddress(Ipv4Address::GetAny(),tcpPort));
    PacketSinkHelper tcpSinkHelper("ns3::TcpSocketFactory",tcpSinkLocalAddress);
    ApplicationContainer tcpSinkApp = tcpSinkHelper.Install(star.GetSpokeNode(star.SpokeCount() - 1));
    tcpSinkApp.Start(Seconds(0.0));
    tcpSinkApp.Stop(Seconds(100.0));

    OnOffHelper clientHelper1("ns3::UdpSocketFactory",Address());
    clientHelper1.SetAttribute("OnTime",StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    clientHelper1.SetAttribute("OffTime",StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    clientHelper1.SetAttribute("PacketSize",UintegerValue(512));
    clientHelper1.SetAttribute("DataRate",DataRateValue(DataRate("5Mb/s")));

    OnOffHelper clientHelper2("ns3::UdpSocketFactory",Address());
    clientHelper2.SetAttribute("OnTime",StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    clientHelper2.SetAttribute("OffTime",StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    clientHelper2.SetAttribute("PacketSize",UintegerValue(512));
    clientHelper2.SetAttribute("DataRate",DataRateValue(DataRate("2Mb/s")));

    //OnOffHelper clientHelper3("ns3::TcpSocketFactory",Address());
    BulkSendHelper clientHelper3("ns3::TcpSocketFactory",Address());
    //clientHelper3.SetAttribute("OnTime",StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    //clientHelper3.SetAttribute("OffTime",StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    clientHelper3.SetAttribute("SendSize",UintegerValue(1024));
    clientHelper3.SetAttribute("MaxBytes",UintegerValue(1024));

    AddressValue udpRemoteAddress (InetSocketAddress (star.GetSpokeIpv4Address(star.SpokeCount() - 1), udpPort));
    AddressValue tcpRemoteAddress (InetSocketAddress (star.GetSpokeIpv4Address(star.SpokeCount() - 1), tcpPort));

    clientHelper1.SetAttribute("Remote",udpRemoteAddress);
    clientHelper2.SetAttribute("Remote",udpRemoteAddress);

    clientHelper3.SetAttribute("Remote",tcpRemoteAddress);

    ApplicationContainer udpSpokeApps;
    
    uint32_t sp = rand() % 10;
    for(uint32_t i = 0;i < 10;i++){
        if(i < sp){
            udpSpokeApps.Add(clientHelper1.Install(star.GetSpokeNode (i)));
        }
        if(i >= sp){
            udpSpokeApps.Add(clientHelper2.Install(star.GetSpokeNode (i)));
        }
    }

    ApplicationContainer tcpSpokeApps;

    tcpSpokeApps.Add(clientHelper3.Install(star.GetSpokeNode (star.SpokeCount() - 2)));

    udpSpokeApps.Start(Seconds(0.0));
    udpSpokeApps.Stop(Seconds(100.0));

    tcpSpokeApps.Start(Seconds(5.0));
    tcpSpokeApps.Stop(Seconds(100.0));

    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(Seconds(100.0));
    Simulator::Run();

    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();
    for(std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i){
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
        if(t.sourceAddress == "10.1.11.2" || t.destinationAddress == "10.1.11.2"){
            std::cout << "Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ") "<<t.protocol<<"\n";
            std::cout << "  Duration:   "<<i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds()<<" Seconds\n";
        }
    }

    Simulator::Destroy();
    return 0;
}