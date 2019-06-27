#include "ns3/log.h"
#include "dqn-queue-disc.h"
#include "ns3/object-factory.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/net-device-queue-interface.h"

namespace ns3{

    NS_LOG_COMPONENT_DEFINE("DqnQueueDisc");

    NS_OBJECT_ENSURE_REGISTERED(DqnQueueDisc);

    TypeId DqnQueueDisc::GetTypeId(void){
        static TypeId tid = TypeId("ns3::DqnQueueDisc")
            .SetParent<QueueDisc>()
            .SetGroupName("TrafficControl")
            .AddConstructor<DqnQueueDisc>()
            .AddAttribute("MaxSize",
                          "The max queue size",
                          QueueSizeValue(QueueSize("1024p")),
                          MakeQueueSizeAccessor(&QueueDisc::SetMaxSize,
                                                &QueueDisc::GetMaxSize),
                          MakeQueueSizeChecker())
            .AddAttribute("QueueNumber",
                          "The max number of Queues",
                          UintegerValue(64),
                          MakeUintegerAccessor(&DqnQueueDisc::queue_number),
                          MakeUintegerChecker<uint8_t>())
            .AddAttribute("DT",
                          "Dynamic threshold",
                          UintegerValue(1024),
                          MakeUintegerAccessor(&DqnQueueDisc::DT),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("BPR",
                          "Byte per round",
                          UintegerValue(4096),
                          MakeUintegerAccessor(&DqnQueueDisc::BPR),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("TULow",
                          "low utilization",
                          DoubleValue(0.2),
                          MakeDoubleAccessor(&DqnQueueDisc::tu_low),
                          MakeDoubleChecker())
            .AddAttribute("Delta",
                          "delta value",
                          UintegerValue(50),
                          MakeUintegerAccessor(&DqnQueueDisc::delta),
                          MakeUintegerChecker<uint32_t>());
        return tid;
    }

    DqnQueueDisc::DqnQueueDisc()
        :QueueDisc(QueueDiscSizePolicy::MULTIPLE_QUEUES,QueueSizeUnit::PACKETS),
        curr(0),n(1),n_star(1){
        NS_LOG_FUNCTION(this);
    }

    DqnQueueDisc::~DqnQueueDisc(){
        NS_LOG_FUNCTION(this);
    }

    bool
    DqnQueueDisc::DoEnqueue(Ptr<QueueDiscItem> item){
        
        NS_LOG_FUNCTION(this << item);

        //std::cout<<"n: "<< (int)n<<"\n";

        uint32_t hash_values[4];
        for(uint8_t i = 0;i < 4;i++){
            hash_values[i] = item -> Hash(i) % 16384;
        }

        uint32_t count_min = count_min_sketch[0][hash_values[0]];
        for(uint8_t i = 0;i < 4;i++){
            if(count_min > count_min_sketch[i][hash_values[i]]){
                count_min = count_min_sketch[i][hash_values[i]];
            }
        }

        uint32_t bid = (count_min < BPR * curr) ? BPR * curr : count_min;
        bid = bid + item -> GetSize();

        uint32_t pkt_round = bid / BPR;

        uint32_t q1_len;

        bool retval;

        if(pkt_round - curr >= n){
            if(n == queue_number){
                NS_LOG_LOGIC("lack of queues -- dropping pkt");
                DropBeforeEnqueue (item, QUEUE_EXCEEDED_DROP);
                return false;
            }else{
                if(n == n_star){
                    //q1_len = GetInternalQueue(((curr % queue_number) + 1) % queue_number) -> GetNPackets();
                    double cor = 0;
                    for(uint8_t i = 0;i < n;i++){
                        cor = cor + 1.0 / (2.0 * (i + 1));
                    }
                    double temp_tu = 1 - (DT / 1024.0);
                    double tu = temp_tu / cor;
                    if(tu < tu_low){
                        n++;
                        n_star++;
                        retval = GetInternalQueue(((curr % queue_number) + pkt_round - curr) % queue_number) -> Enqueue(item);
                        if(retval){
                            for(uint8_t i = 0;i < 4;i++){
                                if(bid > count_min_sketch[i][hash_values[i]]){
                                    count_min_sketch[i][hash_values[i]] = bid;
                                }
                            }
                            DT--;
                        }
                        return retval;
                    }else{
                        NS_LOG_LOGIC("lack of queues -- dropping pkt");
                        DropBeforeEnqueue (item, QUEUE_EXCEEDED_DROP);
                        return false;
                    }
                }else{
                    NS_LOG_LOGIC("lack of queues -- dropping pkt");
                    DropBeforeEnqueue (item, QUEUE_EXCEEDED_DROP);
                    return false;
                }
            }
        }else{
            if(GetInternalQueue(((curr % queue_number) + pkt_round - curr) % queue_number) -> GetNPackets() + 1 > DT){
                NS_LOG_LOGIC ("Queue full -- dropping pkt");
                DropBeforeEnqueue (item, LIMIT_EXCEEDED_DROP);
                retval = false;
            }else{
                retval = GetInternalQueue(((curr % queue_number) + pkt_round - curr) % queue_number) -> Enqueue(item);
                if(retval){
                    for(uint8_t i = 0;i < 4;i++){
                        if(bid > count_min_sketch[i][hash_values[i]]){
                            count_min_sketch[i][hash_values[i]] = bid;
                        }
                    }
                    DT--;
                }
            }

            if(n == n_star && n_star > 1){
                q1_len = GetInternalQueue(((curr % queue_number) + 1) % queue_number) -> GetNPackets();
                if(q1_len > DT - delta){
                    n_star--;
                }
            }
            return retval;
        }
    }

    Ptr<QueueDiscItem>
    DqnQueueDisc::DoDequeue(void){

        NS_LOG_FUNCTION(this);

        Ptr<QueueDiscItem> item;
        for(uint8_t i = 0;i < queue_number;i++){
            if((item = GetInternalQueue(curr % queue_number) -> Dequeue()) != 0){
                DT++;
                return item;
            }
            curr++;
            n = n_star;
        }

        NS_LOG_LOGIC("Queues empty");
        return item;
    }

    Ptr<const QueueDiscItem>
    DqnQueueDisc::DoPeek(void){

        NS_LOG_FUNCTION(this);

        Ptr<const QueueDiscItem> item;
        for(uint8_t i = 0;i < queue_number;i++){
            if((item = GetInternalQueue(curr % queue_number)->Peek()) != 0){
                return item;
            }
        }

        NS_LOG_LOGIC("Queues empty");
        return item;
    }

    bool
    DqnQueueDisc::CheckConfig(void){
        NS_LOG_FUNCTION(this);
        if(GetNQueueDiscClasses() > 0){
            NS_LOG_ERROR("DqnQueueDisc cannot have classes");
            return false;
        }

        if(GetNPacketFilters() > 0){
            NS_LOG_ERROR("DqnQueueDisc cannot have filter");
            return false;
        }

        if(GetNInternalQueues() == 0){
            for(uint8_t i = 0;i < queue_number;i++){
                AddInternalQueue(CreateObjectWithAttributes<DropTailQueue<QueueDiscItem> >
                                ("MaxSize",QueueSizeValue(GetMaxSize())));
            }
        }

        if(GetNInternalQueues() != queue_number){
            NS_LOG_ERROR("DqnQueueDisc needs queue_number internal queues");
            return false;
        }

        return true;
    }

    void
    DqnQueueDisc::InitializeParams(void){
        NS_LOG_FUNCTION(this);
    }

}