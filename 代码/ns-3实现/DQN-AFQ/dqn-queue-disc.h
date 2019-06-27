#ifndef DQN_H
#define DQN_H

#include "ns3/queue-disc.h"

namespace ns3{
    class DqnQueueDisc : public QueueDisc{
        public:
            static TypeId GetTypeId(void);

            DqnQueueDisc();

            virtual ~DqnQueueDisc();

            static constexpr const char* LIMIT_EXCEEDED_DROP = "Queue disc limit exceeded";
            static constexpr const char* QUEUE_EXCEEDED_DROP = "Queue number limit exceeded";

        private:
            virtual bool DoEnqueue(Ptr<QueueDiscItem> item);
            virtual Ptr<QueueDiscItem> DoDequeue(void);
            virtual Ptr<const QueueDiscItem> DoPeek (void);
            virtual bool CheckConfig(void);
            virtual void InitializeParams (void);

            uint32_t count_min_sketch[4][16384];

            uint32_t curr;
            uint32_t DT;
            uint8_t queue_number;
            uint8_t n;
            uint8_t n_star;
            uint32_t delta;
            uint32_t BPR;
            double tu_low;
    };
}

#endif