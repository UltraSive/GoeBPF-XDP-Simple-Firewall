#include "../headers/bpf_helpers.h"
#include <linux/tcp.h> // Include the TCP header definition
#include <linux/udp.h> // Include the UDP header definition
#include <stdint.h>    // Include this header for uint16_t

// Ethernet header
struct ethhdr
{
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr
{
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));

/*
 * Stats collection for monitoring performance.
 */
// BPF map for storing total bytes blocked and passed
BPF_MAP_DEF(totalByteStats) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 2, // You need 2 entries for blocked and passed bytes
};
BPF_MAP_ADD(totalByteStats);

__attribute__((always_inline)) void update_byte_stats(__u32 map_key, __u64 packet_size)
{
  __u64 *byte_counter = bpf_map_lookup_elem(&totalByteStats, &map_key);
  if (byte_counter)
  {
    *byte_counter += packet_size;
    bpf_map_update_elem(&totalByteStats, &map_key, byte_counter, BPF_ANY);
  }
}

// BPF map for storing total bytes blocked and passed
BPF_MAP_DEF(totalPktStats) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 5, 
};
BPF_MAP_ADD(totalPktStats);

__attribute__((always_inline)) void update_packet_stats(__u32 map_key)
{
  __u64 *packet_counter = bpf_map_lookup_elem(&totalPktStats, &map_key);
  if (packet_counter)
  {
    *packet_counter += 1;
    bpf_map_update_elem(&totalPktStats, &map_key, packet_counter, BPF_ANY);
  }
}

/*
 * Maps for the rules that the XDP programs needs to block and allow.
 */
// BPF sourcelist Map
BPF_MAP_DEF(sourcelist) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = 1, // Small value size (1 byte) since we don't need to store significant data. If we know the key exists we can pass it.
    .max_entries = 16,
};
BPF_MAP_ADD(sourcelist);

// BPF addressPair Map key structure
struct ipPair
{
  __u32 source_address;
  __u32 destination_address;
};

// BPF addressPair Map
BPF_MAP_DEF(addressPair) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct ipPair),
    .value_size = 1, // Small value size (1 byte) since we don't need to store significant data. If we know the key exists we can pass it.
    .max_entries = 16,
};
BPF_MAP_ADD(addressPair);

// Define a structure to hold the information you want to associate with each entry.
struct punch_key
{
  __u32 address; // 32-bit IP address
  __u16 port;    // 16-bit Port number
  __u8  protocol; // 8-bit Protocol number
  __u8  padding;
};

struct punch_value
{
  __u8 pass;      // 8-bit allow/block value
  __u32 pps;       // PPS allowed
  __u64 previous; // 64-bit kernel ns time
};

// BPF punch Map
BPF_MAP_DEF(punch_list) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct punch_key),
    .value_size = sizeof(struct punch_value), // Small value size (1 byte) since we don't need to store significant data. If we know the key exists we can pass it.
    .max_entries = 1024,
};
BPF_MAP_ADD(punch_list);

// BPF Default behavior Map
BPF_MAP_DEF(defaultBehavior) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = 1, // allow / drop
    .max_entries = 16,
};
BPF_MAP_ADD(defaultBehavior);

/**
 * Function to lookup punch data in the punch_list map.
 * 2 results in no action.
 * 1 to pass.
 * 0 to drop.
**/ 
__u64 lookup_punch_data(__u32 daddr, __u16 dport, __u8 protocol, struct bpf_map_def *punch_list)
{
  int authorized = 2; // 2 results in no action; 1 to pass; 0 to drop.

  __u64 current_ns = bpf_ktime_get_ns();

  struct punch_key punch_key_ctx;
  memset(&punch_key_ctx, 0, sizeof(punch_key_ctx));
  punch_key_ctx.address = daddr;
  punch_key_ctx.port = dport;
  punch_key_ctx.protocol = protocol;

  // Lookup Punch map
  __u64 *punch_rule_idx = bpf_map_lookup_elem(punch_list, &punch_key_ctx);
  if (punch_rule_idx)
  {
    // Matched, increase match counter for matched "rule"
    __u8 pass = *(__u8 *)punch_rule_idx; // make verifier happy

    // Move the pointer to the next 32-bit value (pps)
    punch_rule_idx = (__u64 *)((__u8 *)punch_rule_idx + sizeof(__u8));
    __u32 pps = *(__u32 *)punch_rule_idx;

    // Move the pointer to the next 64-bit value (previous)
    punch_rule_idx = (__u64 *)((__u8 *)punch_rule_idx + sizeof(__u32));
    __u64 previous_ns = *(__u64 *)punch_rule_idx;
    // Check if the PPS rate is within limits
    if (pps == 0)
    {
      authorized = pass; // Allow the packet
    }
    else if (current_ns - previous_ns >= (1000000000 / pps)) // 1 second in nanoseconds
    {
      // Update the previous_ns value
      previous_ns = current_ns;
      bpf_map_update_elem(punch_list, &punch_key_ctx, &previous_ns, BPF_ANY);
      authorized = pass; // Allow the packet
    }
    else
    {
      authorized = 0; // Drop the packet due to rate limiting
    }
  }

  return authorized;
}

// XDP program //
SEC("xdp")
int firewall(struct xdp_md *ctx)
{
  __u32 key_bytes_dropped = 0;
  __u32 key_bytes_passed = 1;

  __u32 key_packets_dropped = 0;
  __u32 key_packets_passed = 1;
  __u32 key_packets_aborted = 2;
  __u32 key_packets_tx = 3;
  __u32 key_packets_redirect = 4;

  const char fmt_str[] = "Hello, world, from BPF!";
  bpf_printk(fmt_str, sizeof(fmt_str));

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Only IPv4 supported for this example
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end)
  {
    // Malformed Ethernet header
    update_packet_stats(key_packets_aborted);
    return XDP_ABORTED;
  }

  if (ether->h_proto != 0x08U)
  { // htons(ETH_P_IP) -> 0x08U
    // Non IPv4 traffic
    //update_packet_stats(key_packets_passed);
    return XDP_PASS;
  }

  data += sizeof(*ether);
  struct iphdr *ip = data;
  if (data + sizeof(*ip) > data_end)
  {
    // Malformed IPv4 header
    update_packet_stats(key_packets_aborted);
    return XDP_ABORTED;
  }

  uint16_t src_port = 0;
  uint16_t dst_port = 0;

  data += sizeof(*ip);
  switch (ip->protocol)
  {
  case 0x06: // TCP protocol
  {
    if (data + sizeof(struct tcphdr) > data_end)
    {
      // Malformed TCP header
      update_packet_stats(key_packets_aborted);
      return XDP_ABORTED;
    }
    struct tcphdr *tcp = data;

    src_port = tcp->source;
    dst_port = tcp->dest;

    break;
  }
  case 0x11: // UDP protocol
  {
    if (data + sizeof(struct udphdr) > data_end)
    {
      // Malformed UDP header
      update_packet_stats(key_packets_aborted);
      return XDP_ABORTED;
    }
    struct udphdr *udp = data;

    src_port = udp->source;
    dst_port = udp->dest;
    break;
  }
  case 0x01: // ICMP protocol
    // We will leave the dst_port = 0 as it is the placeholder we will use for entries for punching ICMP.
    break;
  default:
    // Other protocols, you can handle or ignore them based on your requirements
    update_packet_stats(key_packets_passed);
    update_byte_stats(key_bytes_passed, ip->tot_len);
    return XDP_PASS;
  }

  // Structure object to hold the packet header data temporarily
  __u32 saddr = ip->saddr;
  __u32 daddr = ip->daddr;
  __u16 dport = dst_port;
  __u8 protocol = ip->protocol;

  // Structure object to hold the blocklist data in MAP_LPM_TRIE format
  struct
  {
    __u32 prefixlen;
    __u32 saddr;
  } key;

  key.prefixlen = 32;
  key.saddr = saddr;

  // Lookup SRC IP in sourcelist IPs
  __u64 *source_rule_idx = bpf_map_lookup_elem(&sourcelist, &key);
  if (source_rule_idx)
  {
    // Matched, increase match counter for matched "rule"
    __u8 index = *(__u8 *)source_rule_idx; // make verifier happy
    if (index == 1)
    {
      update_packet_stats(key_packets_passed);
      update_byte_stats(key_bytes_passed, ip->tot_len);
      return XDP_PASS;
    }
    else if (index == 0)
    {
      update_packet_stats(key_packets_dropped);
      update_byte_stats(key_bytes_dropped, ip->tot_len);
      return XDP_DROP;
    }
  }

  // Structure object to hold the ipPair data format
  struct ipPair pair_key_ctx;
  memset(&pair_key_ctx, 0, sizeof(pair_key_ctx));
  pair_key_ctx.source_address = saddr;
  pair_key_ctx.destination_address = daddr;

  // Lookup SRC IP in allowlisted IPs
  __u64 *pair_rule_idx = bpf_map_lookup_elem(&addressPair, &pair_key_ctx);
  if (pair_rule_idx)
  {
    // Matched, increase match counter for matched "rule"
    __u8 index = *(__u8 *)pair_rule_idx; // make verifier happy
    if (index == 1)
    {
      update_packet_stats(key_packets_passed);
      update_byte_stats(key_bytes_passed, ip->tot_len);
      return XDP_PASS;
    }
    else if (index == 0)
    {
      update_packet_stats(key_packets_dropped);
      update_byte_stats(key_bytes_dropped, ip->tot_len);
      return XDP_DROP;
    }
  }

  int punchPass = lookup_punch_data(daddr, dport, protocol, &punch_list);

  if (punchPass == 1)
  {
    update_packet_stats(key_packets_passed);
    update_byte_stats(key_bytes_passed, ip->tot_len);
    return XDP_PASS;
  }
  else if (punchPass == 0)
  {
    update_packet_stats(key_packets_dropped);
    update_byte_stats(key_bytes_dropped, ip->tot_len);
    return XDP_DROP;
  }

  // Lookup default behavior of IP rules
  struct
  {
    __u32 prefixlen;
    __u32 saddr;
  } dest_key;

  dest_key.prefixlen = 32;
  dest_key.saddr = daddr;

  __u64 *default_behavior_idx = bpf_map_lookup_elem(&defaultBehavior, &dest_key);
  if (default_behavior_idx)
  {
    // Matched, increase match counter for matched "rule"
    __u8 index = *(__u8 *)default_behavior_idx; // make verifier happy
    if (index == 1)
    {
      update_packet_stats(key_packets_passed);
      update_byte_stats(key_bytes_passed, ip->tot_len);
      return XDP_PASS;
    }
  }

  // This accounts for if the default behavior is to drop all not punched or not specified
  update_packet_stats(key_packets_dropped);
  update_byte_stats(key_bytes_dropped, ip->tot_len);
  return XDP_DROP;
}