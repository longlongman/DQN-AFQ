#include "ns3/log.h"
#include "afq-queue-disc.h"
#include "ns3/object-factory.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/net-device-queue-interface.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("AfqQueueDisc");

NS_OBJECT_ENSURE_REGISTERED(AfqQueueDisc);

TypeId AfqQueueDisc::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::AfqQueueDisc")
      .SetParent<QueueDisc>()
      .SetGroupName("TrafficControl")
      .AddConstructor<AfqQueueDisc>()
      .AddAttribute("MaxSize",
                    "The max queue size",
                    QueueSizeValue(QueueSize("1024p")),
                    MakeQueueSizeAccessor(&QueueDisc::SetMaxSize,
                                          &QueueDisc::GetMaxSize),
                    MakeQueueSizeChecker())
      .AddAttribute("QueueNumber",
                    "The number of Queues",
                    UintegerValue(64),
                    MakeUintegerAccessor(&AfqQueueDisc::queue_number),
                    MakeUintegerChecker<uint8_t>())
      .AddAttribute("DT",
                    "Dynamic threshold",
                    UintegerValue(1024),
                    MakeUintegerAccessor(&AfqQueueDisc::DT),
                    MakeUintegerChecker<uint32_t>())
      .AddAttribute("BPR",
                    "Byte per round",
                    UintegerValue(4096),
                    MakeUintegerAccessor(&AfqQueueDisc::BPR),
                    MakeUintegerChecker<uint32_t>());
    return tid;
}

AfqQueueDisc::AfqQueueDisc()
  :QueueDisc(QueueDiscSizePolicy::MULTIPLE_QUEUES,QueueSizeUnit::PACKETS),
   curr(0)
{
    NS_LOG_FUNCTION(this);
}

AfqQueueDisc::~AfqQueueDisc()
{
    NS_LOG_FUNCTION(this);
}

bool 
AfqQueueDisc::DoEnqueue(Ptr<QueueDiscItem> item)
{
    NS_LOG_FUNCTION(this << item);

    //afq algorithm
    uint32_t hash_values[4];
    for(uint8_t i = 0;i < 4;i++)
      {
          hash_values[i] = item -> Hash(i) % 16384;
      }

    // uint32_t hash_value1 = item -> Hash(0) % 16384;
    // uint32_t hash_value2 = item -> Hash(1) % 16384;
    // uint32_t hash_value3 = item -> Hash(2) % 16384;
    // uint32_t hash_value4 = item -> Hash(3) % 16384;

    uint32_t count_min = count_min_sketch[0][hash_values[0]];
    for(uint8_t i = 0;i < 4;i++)
      {
          if(count_min > count_min_sketch[i][hash_values[i]])
            {
                count_min = count_min_sketch[i][hash_values[i]];
            }
      }

    //NS_LOG_UNCOND("curr:"<<curr);

    uint32_t bid = (count_min < BPR * curr) ? BPR * curr : count_min;
    bid =  bid + item -> GetSize();
    //NS_LOG_UNCOND("item size:"<<item -> GetSize()<<hash_values[0]);
    uint32_t pkt_round = bid / BPR;
    if(pkt_round - curr >= queue_number)
      {
          NS_LOG_LOGIC("lack of queues -- dropping pkt");
          DropBeforeEnqueue (item, QUEUE_EXCEEDED_DROP);
          return false;
      }

    if(GetInternalQueue(pkt_round % queue_number)->GetNPackets() + 1 > DT)
      {
          NS_LOG_LOGIC ("Queue full -- dropping pkt");
          DropBeforeEnqueue (item, LIMIT_EXCEEDED_DROP);
          return false;
      }

    bool retval = GetInternalQueue(pkt_round % queue_number)->Enqueue(item);

    if(retval)
      {
          for(uint8_t i = 0;i < 4;i++)
            {
                if(bid > count_min_sketch[i][hash_values[i]])
                  {
                      count_min_sketch[i][hash_values[i]] = bid;
                  }
            }
            DT = DT - 1;
      }
    
    NS_LOG_LOGIC ("Number packets " << GetInternalQueue (pkt_round % queue_number)->GetNPackets ());
    NS_LOG_LOGIC ("Number bytes " << GetInternalQueue (pkt_round % queue_number)->GetNBytes ());

    return retval;
}

Ptr<QueueDiscItem>
AfqQueueDisc::DoDequeue(void)
{
    NS_LOG_FUNCTION(this);

    //afq algorithm
    Ptr<QueueDiscItem> item;
    for(uint8_t i = 0;i < queue_number;i++)
      {
          if((item = GetInternalQueue(curr % queue_number)->Dequeue()) != 0)
            {
                DT = DT + 1;
                return item;
            }
          curr = curr + 1;
      }

    NS_LOG_LOGIC("Queues empty");
    return item;
}

Ptr<const QueueDiscItem>
AfqQueueDisc::DoPeek(void)
{
    NS_LOG_FUNCTION(this);

    //multi queues
    Ptr<const QueueDiscItem> item;
    for(uint8_t i = 0;i < queue_number;i++)
      {
          if((item = GetInternalQueue(curr % queue_number)->Peek()) != 0)
            {
                return item;
            }
      }

    NS_LOG_LOGIC("Queues empty");
    return item;
}

bool
AfqQueueDisc::CheckConfig(void)
{
    NS_LOG_FUNCTION(this);
    if(GetNQueueDiscClasses() > 0)
      {
          NS_LOG_ERROR("AfqQueueDisc cannot have classes");
          return false;
      }

    if(GetNPacketFilters() > 0)
      {
          NS_LOG_ERROR("AfqQueueDisc cannot have filter");
          return false;
      }

    if(GetNInternalQueues() == 0)
      {
          // add 8 DropTail queue
          for(uint8_t i = 0;i < queue_number;i++)
            {
                AddInternalQueue (CreateObjectWithAttributes<DropTailQueue<QueueDiscItem> >
                          ("MaxSize", QueueSizeValue (GetMaxSize ())));
            }
      }

    if(GetNInternalQueues() != queue_number)
      {
          NS_LOG_ERROR("AfqQueueDisc at least have queue_number internal queues");
      }

    return true;
}

void
AfqQueueDisc::InitializeParams(void)
{
    NS_LOG_FUNCTION(this);
}

}
