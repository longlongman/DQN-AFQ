/* -*- P4_14 -*- */
#define ETHERTYPE_IPV4 0x0800
// #define TCP_PROTO 0x06
#define UDP_PROTO 0x11
#define CM_ROW_ELEM_COUNT 16384
#define BPR 4096
#define NQ 8
#define MAX_PORT 2

// ethernet header define
header_type ethernet_t{
    fields{
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;

// ipv4 header define
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

//upd header define
header_type udp_t{
    fields{
        srcPort : 16;
        dstPort : 16;
        udplen : 16;
        udpchk : 16;
    }
}
header udp_t udp;

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

//calculation of hashvalue
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

//count min sketch datastruct
register r1{width : 32; instance_count : CM_ROW_ELEM_COUNT;}
register r2{width : 32; instance_count : CM_ROW_ELEM_COUNT;}
register r3{width : 32; instance_count : CM_ROW_ELEM_COUNT;}
register r4{width : 32; instance_count : CM_ROW_ELEM_COUNT;}
register curr{width : 32;instance_count : MAX_PORT;}


// temp var packet relate
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

header_type bid_metadata_t{
    fields{
        bid : 32;
        curr : 32;
        pkt_round : 32;
    }
}
metadata bid_metadata_t bid_metadata;

// architecture relate metadata
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

//queue metadata
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

header_type debug_t{
    fields{
        pkt_round : 32;
        enq_qdepth : 16;
        deq_qdepth : 16;
        bid : 32;
        curr : 32;
        qid : 8;
    }
}
header debug_t debug;

//define parser statemachine
parser start{
    return parse_ethernet;
}

parser parse_ethernet{
    extract(ethernet);
    return select(latest.etherType){
        ETHERTYPE_IPV4 : parse_ipv4;
    }
}

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

parser parse_ipv4{
    extract(ipv4);
    return select(latest.protocol){
        UDP_PROTO : parse_udp;
        default : ingress;
    }
}

parser parse_udp{
    extract(udp);
    return parse_debug;
}

parser parse_debug{
    extract(debug);
    return ingress;
}

//drop the packet
action do_drop(){
    drop();
}

table drop_table{
    actions{
        do_drop;
    }
}

action do_forward(nextMac,port){
    modify_field(standard_metadata.egress_spec,port);
    modify_field(ethernet.srcAddr,ethernet.dstAddr);
    modify_field(ethernet.dstAddr,nextMac);
    modify_field(ipv4.ttl,ipv4.ttl - 1);
}

//table used to implement ip forward
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
    // modify_field(counter_table_metadata.h_v3,ipv4.hdrChecksum % CM_ROW_ELEM_COUNT);
    // modify_field(counter_table_metadata.h_v4,udp.udpchk % CM_ROW_ELEM_COUNT);
    modify_field_with_hash_based_offset(counter_table_metadata.h_v3,0,hashvalue3,CM_ROW_ELEM_COUNT);
    modify_field_with_hash_based_offset(counter_table_metadata.h_v4,0,hashvalue4,CM_ROW_ELEM_COUNT);
}

table cal_hash{
    actions{
        do_cal_hash;
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
    register_read(bid_metadata.curr,curr,standard_metadata.egress_spec - 1);
}

table get_curr{
    actions{
        do_get_curr;
    }
}

action do_get_bid1(){
    modify_field(bid_metadata.bid,counter_table_metadata.count_min);
}

table get_bid1{
    actions{
        do_get_bid1;
    }
}

action do_get_bid2(){
    modify_field(bid_metadata.bid,BPR * bid_metadata.curr);
}

table get_bid2{
    actions{
        do_get_bid2;
    }
}

action do_update_bid(){
    add_to_field(bid_metadata.bid,standard_metadata.packet_length);
}

table update_bid{
    actions{
        do_update_bid;
    }
}

action do_get_pkt_round(){
    modify_field(bid_metadata.pkt_round,bid_metadata.bid / BPR);
}

table get_pkt_round{
    actions{
        do_get_pkt_round;
    }
}

action do_update_pri(){
    modify_field(intrinsic_metadata.priority,NQ - 1 - bid_metadata.pkt_round % NQ);
}

table update_pri{
    actions{
        do_update_pri;
    }
}

action do_update_count1(){
    modify_field(counter_table_metadata.count1,bid_metadata.bid);
}

table update_count1{
    actions{
        do_update_count1;
    }
}

action do_update_count2(){
    modify_field(counter_table_metadata.count2,bid_metadata.bid);
}

table update_count2{
    actions{
        do_update_count2;
    }
}

action do_update_count3(){
    modify_field(counter_table_metadata.count3,bid_metadata.bid);
}

table update_count3{
    actions{
        do_update_count3;
    }
}

action do_update_count4(){
    modify_field(counter_table_metadata.count4,bid_metadata.bid);
}

table update_count4{
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

action do_update_curr(){
    register_write(curr,standard_metadata.egress_port - 1,bid_metadata.pkt_round + 1);
}

table update_curr{
    actions{
        do_update_curr;
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

action do_add_debug(){
    add_header(debug);
    modify_field(debug.bid,bid_metadata.bid);
    modify_field(debug.pkt_round,bid_metadata.pkt_round);
    modify_field(debug.curr,bid_metadata.curr);
}

table add_debug{
    actions{
        do_add_debug;
    }
}

action do_update_bebug(){
    modify_field(debug.qid,queueing_metadata.qid);
    modify_field(debug.deq_qdepth,queueing_metadata.deq_qdepth);
    modify_field(debug.enq_qdepth,queueing_metadata.enq_qdepth);
}

table update_debug{
    actions{
        do_update_bebug;
    }
}

//ingress control
control ingress{
    //make sure the ipv4 packet ttl > 0
    if(ipv4.ttl > 0){
        //forward the packet according to its dstip
        apply(ipv4_forward);
        //make sure switch know how to forward the packet
        if(valid(udp) and standard_metadata.egress_spec != 511){
            //calculate the hashs
            apply(cal_hash);

            //get the count_min from sketch
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
            if(bid_metadata.bid < BPR * bid_metadata.curr){
                apply(get_bid2);
            }
            apply(update_bid);
            apply(get_pkt_round);
            if((bid_metadata.pkt_round - bid_metadata.curr) >= NQ){
                apply(drop_table);
            }else{
                apply(update_pri);
                if(bid_metadata.bid > counter_table_metadata.count1){
                    apply(update_count1);
                }
                if(bid_metadata.bid > counter_table_metadata.count2){
                    apply(update_count2);
                }
                if(bid_metadata.bid > counter_table_metadata.count3){
                    apply(update_count3);
                }
                if(bid_metadata.bid > counter_table_metadata.count4){
                    apply(update_count4);
                }
                apply(update_cm);
                // apply(add_debug);
            }
        }
    }
}

control egress{
    if(valid(udp) and queueing_metadata.deq_qdepth == 0){
        apply(update_curr);
        // apply(update_debug);
    }
    apply(send_frame);
}
