/* -*- P4_14 -*- */

//this p4 program can only deal with udp flows
#define ETHERTYPE_IPV4 0x0800
#define UDP_PROTO 0x11
#define TCP_PROTO 0x06

//the size of count-min skecht is 4 * 4k
#define CM_ROW_ELEM_COUNT 16384

//bytes can be sent per round by each flow
#define BPR 4096

//the number of priority queues each port
#define NQ 8

//the maximum number of ports in our switch
#define MAX_PORT 4

//the started value of n
#define START_N 0

//the maximum value of DT
#define MAX_DT 50

#define DELTA 5

#define Q_LOW 5

//headers the packets originally have
header_type ethernet_t{
    fields{
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;

header_type ipv4_t{
    fields{
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr : 32;
    }
}
header ipv4_t ipv4;

header_type udp_t{
    fields{
        srcPort : 16;
        dstPort : 16;
        udplen : 16;
        udpchk : 16;
    }
}
header udp_t udp;

header_type tcp_t{
    fields{
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}
header tcp_t tcp;

//headers(metadata) we neead but not come with the packets
header_type counter_table_metadata_t{
    fields{
        h_v1 : 16;
        count1 : 32;
        h_v2 : 16;
        count2 : 32;
        h_v3 : 16;
        count3 : 32;
        h_v4 : 16;
        count4 : 32;
        count_min : 32;
    }
}
metadata counter_table_metadata_t counter_table_metadata;

header_type temp_metadata_t{
    fields{
        bid : 32;
        curr : 32;
        pkt_round : 32;
        n_increase : 32;
        n_decrease : 32;
        n : 32;
        n_star : 32;
        DT_increase : 16;
        DT_decrease : 16;
        DT : 16;
        q_increase : 16;
        q_decrease : 16;
        q_len : 16;
        q1_increase : 16;
        q1_decrease : 16;
        q1_len : 16;
        egress_spec : 32;
    }
}
metadata temp_metadata_t temp_metadata;

header_type intrinsic_metadata_t{
    fields{
        ingress_global_timestamp : 48;
        egress_global_timestamp : 48;
        lf_field_list : 8;
        mcast_grp : 16;
        egress_rid : 16;
        resubmit_flag : 8;
        recirculate_flag : 8;
        priority : 8;
    }
}
metadata intrinsic_metadata_t intrinsic_metadata;

header_type queueing_metadata_t{
    fields{
        enq_timestamp : 48;
        enq_qdepth : 16;
        deq_timedelta : 32;
        deq_qdepth : 16;
        qid : 8;
    }
}
metadata queueing_metadata_t queueing_metadata;

//tuple used to calculate hashvalue
field_list hashvalue_list_udp{
    ipv4.srcAddr;
    ipv4.dstAddr;
    udp.srcPort;
    udp.dstPort;
    ipv4.protocol;
}

field_list hashvalue_list_udp2{
    ipv4.srcAddr;
    ipv4.dstAddr;
    udp.srcPort;
    udp.dstPort;
    ethernet.etherType;
}

field_list hashvalue_list_tcp{
    ipv4.srcAddr;
    ipv4.dstAddr;
    tcp.srcPort;
    tcp.dstPort;
    ipv4.protocol;
}

field_list hashvalue_list_tcp2{
    ipv4.srcAddr;
    ipv4.dstAddr;
    tcp.srcPort;
    tcp.dstPort;
    ethernet.etherType;
}

//hashvalues
field_list_calculation hashvalue1{
    input{hashvalue_list_udp;}
    algorithm : crc16;
    output_width : 16;
}

field_list_calculation hashvalue2{
    input{hashvalue_list_udp;}
    algorithm : csum16;
    output_width : 16;
}

field_list_calculation hashvalue3{
    input{hashvalue_list_udp2;}
    algorithm : crc16;
    output_width : 16;
}

field_list_calculation hashvalue4{
    input{hashvalue_list_udp2;}
    algorithm : csum16;
    output_width : 16;
}

field_list_calculation hashvalue5{
    input{hashvalue_list_tcp;}
    algorithm : crc16;
    output_width : 16;
}

field_list_calculation hashvalue6{
    input{hashvalue_list_tcp;}
    algorithm : csum16;
    output_width : 16;
}

field_list_calculation hashvalue7{
    input{hashvalue_list_tcp2;}
    algorithm : crc16;
    output_width : 16;
}

field_list_calculation hashvalue8{
    input{hashvalue_list_tcp2;}
    algorithm : csum16;
    output_width : 16;
}

//update checksum of ipv4 header
field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

//count min sketch datastruct
register r1{width : 32; instance_count : CM_ROW_ELEM_COUNT;}
register r2{width : 32; instance_count : CM_ROW_ELEM_COUNT;}
register r3{width : 32; instance_count : CM_ROW_ELEM_COUNT;}
register r4{width : 32; instance_count : CM_ROW_ELEM_COUNT;}
register curr{width : 32;instance_count : MAX_PORT;}

//n and n*
register ingress_n_increase{width : 32; instance_count : MAX_PORT;}
register egress_n_decrease{width : 32; instance_count : MAX_PORT;}
register n_star{width : 32; instance_count : MAX_PORT;}

//queues length
register ingress_q0_increase{width : 16;instance_count : NQ;}
register egress_q0_decrease{width : 16;instance_count : NQ;}

register ingress_q1_increase{width : 16;instance_count : NQ;}
register egress_q1_decrease{width : 16;instance_count : NQ;}

register ingress_q2_increase{width : 16;instance_count : NQ;}
register egress_q2_decrease{width : 16;instance_count : NQ;}

register ingress_q3_increase{width : 16;instance_count : NQ;}
register egress_q3_decrease{width : 16;instance_count : NQ;}

register ingress_DT_decrease{width : 16;instance_count : MAX_PORT;}
register egress_DT_increase{width : 16;instance_count : MAX_PORT;}

//parser
parser start{
    return parse_ethernet;
}

parser parse_ethernet{
    extract(ethernet);
    return select(latest.etherType){
        ETHERTYPE_IPV4 : parse_ipv4;
    }
}

parser parse_ipv4{
    extract(ipv4);
    return select(latest.protocol){
        UDP_PROTO : parse_udp;
        TCP_PROTO : parse_tcp;
        default : ingress;
    }
}

parser parse_udp{
    extract(udp);
    return ingress;
}

parser parse_tcp{
    extract(tcp);
    return ingress;
}

action do_drop(){
    drop();
}

table drop_table{
    actions{
        do_drop;
    }
}

table drop_table_{
    actions{
        do_drop;
    }
}

table drop_table__{
    actions{
        do_drop;
    }
}

table drop_table___{
    actions{
        do_drop;
    }
}

action do_forward(nextMac,port){
    modify_field(standard_metadata.egress_spec,port);
    modify_field(ethernet.dstAddr,nextMac);
    modify_field(ipv4.ttl,ipv4.ttl - 1);
}

table ipv4_forward{
    reads{
        ipv4.dstAddr : lpm;
    }
    actions{
        do_forward;
        do_drop;
    }
}

action do_cal_hash(){
    modify_field_with_hash_based_offset(counter_table_metadata.h_v1,0,hashvalue1,CM_ROW_ELEM_COUNT);
    modify_field_with_hash_based_offset(counter_table_metadata.h_v2,0,hashvalue2,CM_ROW_ELEM_COUNT);
    modify_field_with_hash_based_offset(counter_table_metadata.h_v3,0,hashvalue3,CM_ROW_ELEM_COUNT);
    modify_field_with_hash_based_offset(counter_table_metadata.h_v4,0,hashvalue4,CM_ROW_ELEM_COUNT);
}

table cal_hash{
    actions{
        do_cal_hash;
    }
}

action do_cal_hash_(){
    modify_field_with_hash_based_offset(counter_table_metadata.h_v1,0,hashvalue5,CM_ROW_ELEM_COUNT);
    modify_field_with_hash_based_offset(counter_table_metadata.h_v2,0,hashvalue6,CM_ROW_ELEM_COUNT);
    modify_field_with_hash_based_offset(counter_table_metadata.h_v3,0,hashvalue7,CM_ROW_ELEM_COUNT);
    modify_field_with_hash_based_offset(counter_table_metadata.h_v4,0,hashvalue8,CM_ROW_ELEM_COUNT);
}

table cal_hash_{
    actions{
        do_cal_hash_;
    }
}

action do_get_counts(){
    register_read(counter_table_metadata.count1,r1,counter_table_metadata.h_v1);
    register_read(counter_table_metadata.count2,r2,counter_table_metadata.h_v2);
    register_read(counter_table_metadata.count3,r3,counter_table_metadata.h_v3);
    register_read(counter_table_metadata.count4,r4,counter_table_metadata.h_v4);
}

table get_counts{
    actions{
        do_get_counts;
    }
}

action do_get_min1(){
    modify_field(counter_table_metadata.count_min,counter_table_metadata.count1);
}

table get_min1{
    actions{
        do_get_min1;
    }
}

action do_get_min2(){
    modify_field(counter_table_metadata.count_min,counter_table_metadata.count2);
}

table get_min2{
    actions{
        do_get_min2;
    }
}

action do_get_min3(){
    modify_field(counter_table_metadata.count_min,counter_table_metadata.count3);
}

table get_min3{
    actions{
        do_get_min3;
    }
}

action do_get_min4(){
    modify_field(counter_table_metadata.count_min,counter_table_metadata.count4);
}

table get_min4{
    actions{
        do_get_min4;
    }
}

action do_get_curr(){
    register_read(temp_metadata.curr,curr,standard_metadata.egress_spec);
}

table get_curr{
    actions{
        do_get_curr;
    }
}

action do_get_bid1(){
    modify_field(temp_metadata.bid,counter_table_metadata.count_min);
}

table get_bid1{
    actions{
        do_get_bid1;
    }
}

action do_get_bid2(){
    modify_field(temp_metadata.bid,BPR * temp_metadata.curr);
}

table get_bid2{
    actions{
        do_get_bid2;
    }
}

action do_update_bid(){
    add_to_field(temp_metadata.bid,standard_metadata.packet_length);
}

table update_bid{
    actions{
        do_update_bid;
    }
}

action do_get_pkt_round(){
    modify_field(temp_metadata.pkt_round,temp_metadata.bid / BPR);
}

table get_pkt_round{
    actions{
        do_get_pkt_round;
    }
}

action do_get_n(){
    register_read(temp_metadata.n_increase,ingress_n_increase,standard_metadata.egress_spec);
    register_read(temp_metadata.n_decrease,egress_n_decrease,standard_metadata.egress_spec);
    modify_field(temp_metadata.n,START_N + temp_metadata.n_increase - temp_metadata.n_decrease);
}

table get_n{
    actions{
        do_get_n;
    }
}

action do_egress_get_n(){
    register_read(temp_metadata.n_increase,ingress_n_increase,standard_metadata.egress_port);
    register_read(temp_metadata.n_decrease,egress_n_decrease,standard_metadata.egress_port);
    modify_field(temp_metadata.n,START_N + temp_metadata.n_increase - temp_metadata.n_decrease);
}

table egress_get_n{
    actions{
        do_egress_get_n;
    }
}

action do_get_n_star(){
    register_read(temp_metadata.n_star,n_star,standard_metadata.egress_spec);
}

table get_n_star{
    actions{
        do_get_n_star;
    }
}

action do_get_n_star_(){
    register_read(temp_metadata.n_star,n_star,temp_metadata.egress_spec);
}

table get_n_star_{
    actions{
        do_get_n_star_;
    }
}

action do_increase_n(){
    register_read(temp_metadata.n_increase,ingress_n_increase,standard_metadata.egress_spec);
    modify_field(temp_metadata.n_increase,temp_metadata.n_increase + 1);
    register_write(ingress_n_increase,standard_metadata.egress_spec,temp_metadata.n_increase);
}

table increase_n{
    actions{
        do_increase_n;
    }
}

action do_increase_n_star(){
    modify_field(temp_metadata.n_star,temp_metadata.n_star + 1);
    register_write(n_star,standard_metadata.egress_spec,temp_metadata.n_star);
}

table increase_n_star{
    actions{
        do_increase_n_star;
    }
}

action do_decrease_n_star(){
    modify_field(temp_metadata.n_star,temp_metadata.n_star - 1);
    register_write(n_star,standard_metadata.egress_spec,temp_metadata.n_star);
}

table decrease_n_star{
    actions{
        do_decrease_n_star;
    }
}

action do_update_pri(){
    modify_field(intrinsic_metadata.priority,temp_metadata.pkt_round - temp_metadata.curr);
}

table update_pri{
    actions{
        do_update_pri;
    }
}

table update_pri_{
    actions{
        do_update_pri;
    }
}

action do_update_count1(){
    modify_field(counter_table_metadata.count1,temp_metadata.bid);
}

table update_count1{
    actions{
        do_update_count1;
    }
}

table update_count1_{
    actions{
        do_update_count1;
    }
}

action do_update_count2(){
    modify_field(counter_table_metadata.count2,temp_metadata.bid);
}

table update_count2{
    actions{
        do_update_count2;
    }
}

table update_count2_{
    actions{
        do_update_count2;
    }
}

action do_update_count3(){
    modify_field(counter_table_metadata.count3,temp_metadata.bid);
}

table update_count3{
    actions{
        do_update_count3;
    }
}

table update_count3_{
    actions{
        do_update_count3;
    }
}

action do_update_count4(){
    modify_field(counter_table_metadata.count4,temp_metadata.bid);
}

table update_count4{
    actions{
        do_update_count4;
    }
}

table update_count4_{
    actions{
        do_update_count4;
    }
}

action do_update_cm(){
    register_write(r1,counter_table_metadata.h_v1,counter_table_metadata.count1);
    register_write(r2,counter_table_metadata.h_v2,counter_table_metadata.count2);
    register_write(r3,counter_table_metadata.h_v3,counter_table_metadata.count3);
    register_write(r4,counter_table_metadata.h_v4,counter_table_metadata.count4);
}

table update_cm{
    actions{
        do_update_cm;
    }
}

table update_cm_{
    actions{
        do_update_cm;
    }
}

action do_decrease_DT(){
    register_read(temp_metadata.DT_decrease,ingress_DT_decrease,standard_metadata.egress_spec);
    modify_field(temp_metadata.DT_decrease,temp_metadata.DT_decrease + 1);
    register_write(ingress_DT_decrease,standard_metadata.egress_spec,temp_metadata.DT_decrease);
} 

table decrease_DT{
    actions{
        do_decrease_DT;
    }
}

table decrease_DT_{
    actions{
        do_decrease_DT;
    }
}

action do_increase_q0(){
    register_read(temp_metadata.q_increase,ingress_q0_increase,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    modify_field(temp_metadata.q_increase,temp_metadata.q_increase + 1);
    register_write(ingress_q0_increase,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ,temp_metadata.q_increase);
}

table increase_q0{
    actions{
        do_increase_q0;
    }
}

table increase_q0_{
    actions{
        do_increase_q0;
    }
}

action do_increase_q1(){
    register_read(temp_metadata.q_increase,ingress_q1_increase,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    modify_field(temp_metadata.q_increase,temp_metadata.q_increase + 1);
    register_write(ingress_q1_increase,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ,temp_metadata.q_increase);
}

table increase_q1{
    actions{
        do_increase_q1;
    }
}

table increase_q1_{
    actions{
        do_increase_q1;
    }
}

action do_increase_q2(){
    register_read(temp_metadata.q_increase,ingress_q2_increase,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    modify_field(temp_metadata.q_increase,temp_metadata.q_increase + 1);
    register_write(ingress_q2_increase,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ,temp_metadata.q_increase);
}

table increase_q2{
    actions{
        do_increase_q2;
    }
}

table increase_q2_{
    actions{
        do_increase_q2;
    }
}

action do_increase_q3(){
    register_read(temp_metadata.q_increase,ingress_q3_increase,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    modify_field(temp_metadata.q_increase,temp_metadata.q_increase + 1);
    register_write(ingress_q3_increase,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ,temp_metadata.q_increase);
}

table increase_q3{
    actions{
        do_increase_q3;
    }
}

table increase_q3_{
    actions{
        do_increase_q3;
    }
}

action do_get_DT(){
    register_read(temp_metadata.DT_increase,egress_DT_increase,standard_metadata.egress_spec);
    register_read(temp_metadata.DT_decrease,ingress_DT_decrease,standard_metadata.egress_spec);
    modify_field(temp_metadata.DT,MAX_DT + temp_metadata.DT_increase - temp_metadata.DT_decrease);
}

table get_DT{
    actions{
        do_get_DT;
    }
}

table get_DT_{
    actions{
        do_get_DT;
    }
}

action do_get_q0(){
    register_read(temp_metadata.q_increase,ingress_q0_increase,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    register_read(temp_metadata.q_decrease,egress_q0_decrease,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    modify_field(temp_metadata.q_len,temp_metadata.q_increase - temp_metadata.q_decrease);
}

table get_q0{
    actions{
        do_get_q0;
    }
}

action do_get_q0_1(){
    register_read(temp_metadata.q1_increase,ingress_q0_increase,((temp_metadata.curr % NQ) + 1) % NQ);
    register_read(temp_metadata.q1_decrease,egress_q0_decrease,((temp_metadata.curr % NQ) + 1) % NQ);
    modify_field(temp_metadata.q1_len,temp_metadata.q1_increase - temp_metadata.q1_decrease);
}

table get_q0_1{
    actions{
        do_get_q0_1;
    }
}

table get_q0_1_{
    actions{
        do_get_q0_1;
    }
}

action do_get_q1(){
    register_read(temp_metadata.q_increase,ingress_q1_increase,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    register_read(temp_metadata.q_decrease,egress_q1_decrease,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    modify_field(temp_metadata.q_len,temp_metadata.q_increase - temp_metadata.q_decrease);
}

table get_q1{
    actions{
        do_get_q1;
    }
}

action do_get_q1_1(){
    register_read(temp_metadata.q1_increase,ingress_q1_increase,((temp_metadata.curr % NQ) + 1) % NQ);
    register_read(temp_metadata.q1_decrease,egress_q1_decrease,((temp_metadata.curr % NQ) + 1) % NQ);
    modify_field(temp_metadata.q1_len,temp_metadata.q1_increase - temp_metadata.q1_decrease);
}

table get_q1_1{
    actions{
        do_get_q1_1;
    }
}

table get_q1_1_{
    actions{
        do_get_q1_1;
    }
}

action do_get_q2(){
    register_read(temp_metadata.q_increase,ingress_q2_increase,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    register_read(temp_metadata.q_decrease,egress_q2_decrease,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    modify_field(temp_metadata.q_len,temp_metadata.q_increase - temp_metadata.q_decrease);
}

table get_q2{
    actions{
        do_get_q2;
    }
}

action do_get_q2_1(){
    register_read(temp_metadata.q1_increase,ingress_q2_increase,((temp_metadata.curr % NQ) + 1) % NQ);
    register_read(temp_metadata.q1_decrease,egress_q2_decrease,((temp_metadata.curr % NQ) + 1) % NQ);
    modify_field(temp_metadata.q1_len,temp_metadata.q1_increase - temp_metadata.q1_decrease);
}

table get_q2_1{
    actions{
        do_get_q2_1;
    }
}

table get_q2_1_{
    actions{
        do_get_q2_1;
    }
}

action do_get_q3(){
    register_read(temp_metadata.q_increase,ingress_q3_increase,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    register_read(temp_metadata.q_decrease,egress_q3_decrease,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    modify_field(temp_metadata.q_len,temp_metadata.q_increase - temp_metadata.q_decrease);
}

table get_q3{
    actions{
        do_get_q3;
    }
}

action do_get_q3_1(){
    register_read(temp_metadata.q1_increase,ingress_q3_increase,((temp_metadata.curr % NQ) + 1) % NQ);
    register_read(temp_metadata.q1_decrease,egress_q3_decrease,((temp_metadata.curr % NQ) + 1) % NQ);
    modify_field(temp_metadata.q1_len,temp_metadata.q1_increase - temp_metadata.q1_decrease);
}

table get_q3_1{
    actions{
        do_get_q3_1;
    }
}

table get_q3_1_{
    actions{
        do_get_q3_1;
    }
}

action do_egress_increase_DT(){
    register_read(temp_metadata.DT_increase,egress_DT_increase,standard_metadata.egress_port);
    modify_field(temp_metadata.DT_increase,temp_metadata.DT_increase + 1);
    register_write(egress_DT_increase,standard_metadata.egress_port,temp_metadata.DT_increase);
}

table egress_increase_DT{
    actions{
        do_egress_increase_DT;
    }
}

action do_decrease_q0(){
    register_read(temp_metadata.q_decrease,egress_q0_decrease,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    modify_field(temp_metadata.q_decrease,temp_metadata.q_decrease + 1);
    register_write(egress_q0_decrease,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ,temp_metadata.q_decrease);
}

table decrease_q0{
    actions{
        do_decrease_q0;
    }
}

action do_decrease_q1(){
    register_read(temp_metadata.q_decrease,egress_q1_decrease,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    modify_field(temp_metadata.q_decrease,temp_metadata.q_decrease + 1);
    register_write(egress_q1_decrease,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ,temp_metadata.q_decrease);
}

table decrease_q1{
    actions{
        do_decrease_q1;
    }
}

action do_decrease_q2(){
    register_read(temp_metadata.q_decrease,egress_q2_decrease,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    modify_field(temp_metadata.q_decrease,temp_metadata.q_decrease + 1);
    register_write(egress_q2_decrease,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ,temp_metadata.q_decrease);
}

table decrease_q2{
    actions{
        do_decrease_q2;
    }
}

action do_decrease_q3(){
    register_read(temp_metadata.q_decrease,egress_q3_decrease,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ);
    modify_field(temp_metadata.q_decrease,temp_metadata.q_decrease + 1);
    register_write(egress_q3_decrease,((temp_metadata.curr % NQ) + intrinsic_metadata.priority) % NQ,temp_metadata.q_decrease);
}

table decrease_q3{
    actions{
        do_decrease_q3;
    }
}

action do_increase_curr(){
    register_read(temp_metadata.curr,curr,standard_metadata.egress_port);
    modify_field(temp_metadata.curr,temp_metadata.curr + 1);
    register_write(curr,standard_metadata.egress_port,temp_metadata.curr);
}

table increase_curr{
    actions{
        do_increase_curr;
    }
}

action do_egress_get_n_star(){
    register_read(temp_metadata.n_star,n_star,standard_metadata.egress_port);
}

table egress_get_n_star{
    actions{
        do_egress_get_n_star;
    }
}

action do_decrease_n(){
    register_read(temp_metadata.n_decrease,egress_n_decrease,standard_metadata.egress_port);
    modify_field(temp_metadata.n_decrease,temp_metadata.n_decrease + 1);
    register_write(egress_n_decrease,standard_metadata.egress_port,temp_metadata.n_decrease);
}

table decrease_n{
    actions{
        do_decrease_n;
    }
}

action rewrite_mac(smac){
    modify_field(ethernet.srcAddr,smac);
}

table send_frame{
    reads{
        standard_metadata.egress_port: exact;
    }
    actions{
        rewrite_mac;
        do_drop;
    }
}

action do_save_egress_spec(){
    modify_field(temp_metadata.egress_spec,standard_metadata.egress_spec);
}

table save_egress_spec{
    actions{
        do_save_egress_spec;
    }
}

control ingress{
    if(valid(ipv4) and ipv4.ttl > 0){
        apply(ipv4_forward);
        if((valid(udp) or valid(tcp)) and standard_metadata.egress_spec != 511){
            if(valid(udp)){
                apply(cal_hash);
            }
            if(valid(tcp)){
                apply(cal_hash_);
            }
            apply(get_counts);
            apply(get_min1);
            if(counter_table_metadata.count_min > counter_table_metadata.count2){
                apply(get_min2);
            }
            if(counter_table_metadata.count_min > counter_table_metadata.count3){
                apply(get_min3);
            }
            if(counter_table_metadata.count_min > counter_table_metadata.count4){
                apply(get_min4);
            }
            apply(get_curr);
            apply(get_bid1);
            if(temp_metadata.bid < BPR * temp_metadata.curr){
                apply(get_bid2);
            }
            apply(update_bid);
            apply(get_pkt_round);
            apply(get_n);
            if((temp_metadata.pkt_round - temp_metadata.curr) >= temp_metadata.n){
                if(temp_metadata.n == NQ){
                    apply(drop_table);
                }else{
                    apply(get_n_star);
                    if(temp_metadata.n == temp_metadata.n_star){
                        apply(get_DT_);
                        if(standard_metadata.egress_spec == 0){
                            apply(get_q0_1_);
                        }
                        if(standard_metadata.egress_spec == 1){
                            apply(get_q1_1_);
                        }
                        if(standard_metadata.egress_spec == 2){
                            apply(get_q2_1_);
                        }
                        if(standard_metadata.egress_spec == 3){
                            apply(get_q3_1_);
                        }
                        if(temp_metadata.q1_len < Q_LOW){
                            apply(increase_n);
                            apply(increase_n_star);
                            apply(update_pri);
                            if(temp_metadata.bid > counter_table_metadata.count1){
                                apply(update_count1);
                            }
                            if(temp_metadata.bid > counter_table_metadata.count2){
                                apply(update_count2);
                            }
                            if(temp_metadata.bid > counter_table_metadata.count3){
                                apply(update_count3);
                            }
                            if(temp_metadata.bid > counter_table_metadata.count4){
                                apply(update_count4);
                            }
                            apply(update_cm);
                            apply(decrease_DT);
                            if(standard_metadata.egress_spec == 0){
                                apply(increase_q0);
                            }
                            if(standard_metadata.egress_spec == 1){
                                apply(increase_q1);
                            }
                            if(standard_metadata.egress_spec == 2){
                                apply(increase_q2);
                            }
                            if(standard_metadata.egress_spec == 3){
                                apply(increase_q3);
                            }
                        }else{
                            apply(drop_table___);
                        }
                    }else{
                        apply(drop_table_);
                    }
                }
            }else{
                apply(update_pri_);
                apply(get_DT);
                if(standard_metadata.egress_spec == 0){
                    apply(get_q0);
                }
                if(standard_metadata.egress_spec == 1){
                    apply(get_q1);
                }
                if(standard_metadata.egress_spec == 2){
                    apply(get_q2);
                }
                if(standard_metadata.egress_spec == 3){
                    apply(get_q3);
                }
                apply(save_egress_spec);
                if(temp_metadata.DT <= temp_metadata.q_len){
                    apply(drop_table__);
                }else{
                    if(temp_metadata.bid > counter_table_metadata.count1){
                        apply(update_count1_);
                    }
                    if(temp_metadata.bid > counter_table_metadata.count2){
                        apply(update_count2_);
                    }
                    if(temp_metadata.bid > counter_table_metadata.count3){
                        apply(update_count3_);
                    }
                    if(temp_metadata.bid > counter_table_metadata.count4){
                        apply(update_count4_);
                    }
                    apply(update_cm_);
                    apply(decrease_DT_);
                    if(standard_metadata.egress_spec == 0){
                        apply(increase_q0_);
                    }
                    if(standard_metadata.egress_spec == 1){
                        apply(increase_q1_);
                    }
                    if(standard_metadata.egress_spec == 2){
                        apply(increase_q2_);
                    }
                    if(standard_metadata.egress_spec == 3){
                        apply(increase_q3_);
                    }
                }
                apply(get_n_star_);
                if(temp_metadata.n == temp_metadata.n_star){
                    if(standard_metadata.egress_spec == 0){
                        apply(get_q0_1);
                    }
                    if(standard_metadata.egress_spec == 1){
                        apply(get_q1_1);
                    }
                    if(standard_metadata.egress_spec == 2){
                        apply(get_q2_1);
                    }
                    if(standard_metadata.egress_spec == 3){
                        apply(get_q3_1);
                    }
                    if(temp_metadata.q1_len > temp_metadata.DT - DELTA){
                        apply(decrease_n_star);
                    }
                }
            }
        }
    }
}

control egress{
    if(valid(udp) or valid(tcp)){
        apply(egress_increase_DT);
        if(standard_metadata.egress_port == 0){
            apply(decrease_q0);
        }
        if(standard_metadata.egress_port == 1){
            apply(decrease_q1);
        }
        if(standard_metadata.egress_port == 2){
            apply(decrease_q2);
        }
        if(standard_metadata.egress_port == 3){
            apply(decrease_q3);
        }
        if(queueing_metadata.deq_qdepth == 0){
            apply(increase_curr);
            apply(egress_get_n_star);
            apply(egress_get_n);
            if(temp_metadata.n > temp_metadata.n_star){
                apply(decrease_n);
            }
        }
    }
    apply(send_frame);
}