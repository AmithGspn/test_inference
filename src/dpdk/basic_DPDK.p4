/*-------------- Modified code changes ---------------*/
// 1. "Reciruclation code" is commented for future purposes.
// 2. "storing the metadata result" is commented for future purposes.

/*-----------------Main-----------------*/ 
#include <core.p4>
#include <dpdk/pna.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;

const bit<32> NB_ENTRIES = 20000;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<64> feature1_t;         // IAT
typedef bit<16> feature2_t;         //packet length
typedef bit<32> feature3_t;         //diff of packet length
typedef bit<8>  inference_result_t; //final classification

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen; 
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

/* TCP header */
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/* UDP header */
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udpTotalLen;
    bit<16> checksum;
}

header recirculation_header_t {
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<8> protocol;
    feature1_t iat;
    feature2_t len;
    feature3_t diffLen;
    inference_result_t ml_result;
}

struct metadata {
    bit<1> isRecirculated;
    bit<32> flow_id;
    bit<64> last_timestamp;
    bit<64> current_timestamp;
    bit<32> last_packet_len;
    bit<32> current_packet_len;

    //remember this info to avoid accessing from udp or tcp
    bit<16> srcPort;
    bit<16> dstPort;

    feature1_t iat;  
    feature3_t diffLen;
    inference_result_t ml_result;   //final classification result
}

struct headers {
    // recirculation_header_t    recirculation_header;
    ethernet_t                ethernet;
    ipv4_t                    ipv4;
    tcp_t                     tcp;
    udp_t                     udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out       headers hdr,
                inout     metadata meta,
                in        pna_main_parser_input_metadata_t istd) {

    state start {
        // transition select(meta.isRecirculated) {
        //     1: parse_recirculation;
        //     0: parse_ethernet;
        // }
        transition parse_ethernet;
    }

    // state parse_recirculation {
    //     packet.extract(hdr.recirc_header);
    //     meta.srcPort = hdr.recirc_header.srcPort;
    //     meta.dstPort = hdr.recirc_header.dstPort;
    //     meta.iat = hdr.recirc_header.iat;
    //     meta.diffLen = hdr.recirc_header.diffLen;
    //     meta.ml_result = hdr.recirc_header.ml_result;
    //     transition parse_ethernet;
    // }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default  : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        //remember src and dst ports to identify this flow
        meta.dstPort = hdr.tcp.dstPort;
        meta.srcPort = hdr.tcp.srcPort;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.dstPort = hdr.udp.dstPort;
        meta.srcPort = hdr.udp.srcPort;
        transition accept;
    }
}

/*-----------------Pre-control-----------------*/
control PreControl(
    in    headers  hdr,
    inout metadata meta,
    in    pna_pre_input_metadata_t  istd,
    inout pna_pre_output_metadata_t ostd)
{
    apply { }
}

/*-----------------Control-----------------*/
control MainControl(
    inout headers hdr,
    inout metadata meta,
    in    pna_main_input_metadata_t istd,
    inout pna_main_output_metadata_t ostd){    
    
    action drop () {
        drop_packet();
    }

    // action ipv4_forward (macAddr_t dstAddr, PortId_t port_id) {
    //     send_to_port(port_id);
    //     hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    //     hdr.ethernet.dstAddr = dstAddr;
    //     hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    // }

    // table ipv4_lpm {
    //     key = { 
    //         hdr.ipv4.dstAddr: lpm;
    //     }
    //     actions = { 
    //         ipv4_forward;
    //         drop;
    //         NoAction;
    //     }
    //     size = 1024;
    //     default_action = drop();
    // }

    /* ml table and its actions for the final result */
    action set_result(inference_result_t val){
        meta.ml_result = val;
    }

    table ml_code{
        key = {
            // meta.iat          : ternary;
            hdr.ipv4.totalLen : ternary;
            meta.diffLen      : ternary;
        }
        actions = {
            set_result;
            NoAction;
        }
       size = NB_ENTRIES;
    }

    Hash<bit<32>> (PNA_HashAlgorithm_t.CRC32) hash;

    action complute_flow_id() {
        meta.flow_id = hash.get_hash((bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, 2048);
    }

    Register<feature1_t, bit<32>>(1024) reg_last_timestamp;
    
    action get_iat(){
        meta.last_timestamp = reg_last_timestamp.read((bit<32>) meta.flow_id); 
        meta.current_timestamp = ((bit<64>)istd.timestamp); 
        if(meta.last_timestamp != 0) { 
            meta.iat = meta.current_timestamp - meta.last_timestamp; 
        } else { 
            meta.iat = 0; 
        } 
        reg_last_timestamp.write((bit<32>)meta.flow_id, meta.current_timestamp); 
    }

    Register<feature3_t, bit<32>>(1024) reg_last_packet_len;

    action get_diff_len(){
        meta.last_packet_len = reg_last_packet_len.read((bit<32>) meta.flow_id); 
        meta.current_packet_len = ((bit<32>) hdr.ipv4.totalLen); 
        if(meta.last_packet_len != 0) { 
            meta.diffLen = meta.current_packet_len - meta.last_packet_len; 
        } else { 
            meta.diffLen = 0; 
        } 
        reg_last_packet_len.write((bit<32>)meta.flow_id, meta.current_packet_len); 
    }

    Register<bit<8>, bit<8>>(1) metadata_register;

    action store_metadata_in_register(bit<8> index, bit<8> value) {
        metadata_register.write(index, value);
    }

    action recirculate_packet(){
        // Code for recirculation_packet (Future purpose)
        // send_to_port(recirculation_port)
    }

    apply {
        if (hdr.ipv4.isValid() ) {
            complute_flow_id();
            get_iat();
            get_diff_len();
            ml_code.apply();
            store_metadata_in_register(0, meta.ml_result);
            // Example: if packet is classified as "MALICIOUS"
            // if(meta.ml_result == "MALICIOUS") {
            //     recirculate_packet();
            // } else {
                // store_metadata_in_register(0, hdr.ipv4.srcAddr ++ hdr.ipv4.dstAddr
                //                       ++ meta.srcPort ++ meta.dstPort
                //                       ++ hdr.ipv4.protocol  ++ 
                //                      (bit<64>)meta.iat ++ hdr.ipv4.totalLen
                //                       ++ meta.diffLen
                //                       ++ meta.ml_result);
            // ipv4_lpm.apply();
            // }
        }
    }
}

/*-----------------Deparser-----------------*/
control MyDeparser(
    packet_out packet,
    inout      headers hdr,
    in         metadata meta,
    in         pna_main_output_metadata_t ostd)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    } 
}

PNA_NIC(
    MyParser(),
    PreControl(),
    MainControl(),
    MyDeparser()
) main;
 