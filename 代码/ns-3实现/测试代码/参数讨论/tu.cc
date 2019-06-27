#include <string>
#include <fstream>
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

NS_LOG_COMPONENT_DEFINE("AfqStarAdvExample");

// void throughput(Ptr<FlowMonitor> monitor,FlowMonitorHelper* flowmon){
//     monitor->CheckForLostPackets();
//     Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon -> GetClassifier());
//     FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();
//     for(std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i){
//         Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
//         //std::cout << "Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
//         //std::cout << "  Tx Packets: " << i->second.txPackets << "\n";
//         //std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
//         //std::cout << "  TxOffered:  " << i->second.txBytes * 8.0 / 100.0 / 1000 / 1000  << " Mbps\n";
//         //std::cout << "  Rx Packets: " << i->second.rxPackets << "\n";
//         //std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
//         //std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / 100.0 / 1000 / 1000  << " Mbps\n";
//         std::cout << "Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
//         std::cout << "  Tx Packets: " << i->second.txPackets << "\n";
//         std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
//         std::cout << "  Rx Packets: " << i->second.rxPackets << "\n";
//         std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
//         std::cout << "  Duration:   "<<i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds()<<" Seconds\n";
//         std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds()- i->second.timeFirstTxPacket.GetSeconds())/1000/1000  << " Mbps\n";
//     }
//     Simulator::Schedule (Seconds (0.5), &throughput,monitor,flowmon);
// }

int main(int argc,char *argv[]){
    
    uint32_t nSpokes = 6;
    bool DqnEnable = false;
    
    CommandLine cmd;
    cmd.AddValue("nSpokes", "Number of nodes to place in the star", nSpokes);
    cmd.AddValue("DqnEnable", "Enable the Dqn QueueDisc",DqnEnable);
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

    uint16_t port = 50000;
    Address sinkLocalAddress(InetSocketAddress(Ipv4Address::GetAny(),port));
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",sinkLocalAddress);
    ApplicationContainer sinkApp = sinkHelper.Install(star.GetSpokeNode(star.SpokeCount() - 1));
    sinkApp.Start(Seconds(0.0));
    sinkApp.Stop(Seconds(100.0));

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

    ApplicationContainer spokeApps;

    AddressValue remoteAddress (InetSocketAddress (star.GetSpokeIpv4Address(star.SpokeCount() - 1), port));
    clientHelper2.SetAttribute("Remote",remoteAddress);
    clientHelper1.SetAttribute("Remote",remoteAddress);
    //spokeApps.Add(clientHelper1.Install(star.GetSpokeNode (1)));

    uint32_t sp = rand() % (nSpokes - 1);
    for(uint32_t i = 1;i < star.SpokeCount() - 1;i++){
        if(i < sp){
            spokeApps.Add(clientHelper2.Install(star.GetSpokeNode (i)));
        }else{
            spokeApps.Add(clientHelper1.Install(star.GetSpokeNode (i)));
        }
    }

    //spokeApps.Get(0) -> SetStartTime (Seconds (0.0));
    //spokeApps.Get(0) -> SetStopTime (Seconds (10.0));

    //spokeApps.Get(1) -> SetStartTime (Seconds (9.0));
    //spokeApps.Get(1) -> SetStopTime (Seconds (25.0));

    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(Seconds(100.0));

    // Simulator::ScheduleNow (&throughput,monitor,&flowmon);
    //throughput(monitor,&flowmon);

    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon -> GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();
    for(std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i){
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
        std::cout << "Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
        std::cout << "  Tx Packets: " << i->second.txPackets << "\n";
        std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
        std::cout << "  Rx Packets: " << i->second.rxPackets << "\n";
        std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
        std::cout << "  Duration:   "<<i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds()<<" Seconds\n";
        std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds()- i->second.timeFirstTxPacket.GetSeconds())/1000/1000  << " Mbps\n";
    }

    Simulator::Run();

    Simulator::Destroy();
    return 0;
}