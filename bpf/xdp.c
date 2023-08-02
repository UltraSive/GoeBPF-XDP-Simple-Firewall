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

// BPF Blocklist Map
BPF_MAP_DEF(blocklist) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = 32, // Small value size (1 byte) since we don't need to store significant data. If we know the key exists we can pass it.
    .max_entries = 16,
};
BPF_MAP_ADD(blocklist);

// BPF allowedIPs Map
BPF_MAP_DEF(allowlist) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = 32, // Small value size (1 byte) since we don't need to store significant data. If we know the key exists we can pass it.
    .max_entries = 16,
};
BPF_MAP_ADD(allowlist);

// Define a structure to hold the information you want to associate with each entry.
struct punch_key
{
  __u32 address; // 32-bit IP address
  __u16 port;    // 16-bit Port number
  __u8 protocol; // 8-bit Protocol number
  __u8 padding;
};

// BPF punch Map
BPF_MAP_DEF(punch_list) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct punch_key),
    .value_size = 32, // Small value size (1 byte) since we don't need to store significant data. If we know the key exists we can pass it.
    .max_entries = 1024,
};
BPF_MAP_ADD(punch_list);

// Function to lookup punch data in the punch_list map
__u64 lookup_punch_data(__u32 daddr, __u16 dport, __u8 protocol, struct bpf_map_def *punch_list)
{
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
    __u32 index = *(__u32 *)punch_rule_idx; // make verifier happy
    // Return 1 to indicate a match
    return 1;
  }

  // Return 0 to indicate no match
  return 0;
}

// XDP program //
SEC("xdp")
int firewall(struct xdp_md *ctx)
{
  const char fmt_str[] = "Hello, world, from BPF!";
  bpf_printk(fmt_str, sizeof(fmt_str));

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Only IPv4 supported for this example
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end)
  {
    // Malformed Ethernet header
    return XDP_ABORTED;
  }

  if (ether->h_proto != 0x08U)
  { // htons(ETH_P_IP) -> 0x08U
    // Non IPv4 traffic
    return XDP_PASS;
  }

  data += sizeof(*ether);
  struct iphdr *ip = data;
  if (data + sizeof(*ip) > data_end)
  {
    // Malformed IPv4 header
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
      return XDP_ABORTED;
    }
    struct udphdr *udp = data;

    src_port = udp->source;
    dst_port = udp->dest;
    break;
  }
  case 0x01: // ICMP protocol
    // Structure object to hold the punch data temporarily
    /*
    __u32 icmp_daddr = ip->daddr;
    __u16 icmp_dport = 0;
    __u8 icmp_protocol = ip->protocol;

    __u64 icmp_value = lookup_punch_data(icmp_daddr, icmp_dport, icmp_protocol, &punch_list);

    if (icmp_value != 0)
    {
      return XDP_PASS;
    }
    */
    break;
  default:
    // Other protocols, you can handle or ignore them based on your requirements
    return XDP_PASS;
  }

  /*
  Structure object to hold the blocklist data in MAP_LPM_TRIE format
  */
  struct
  {
    __u32 prefixlen;
    __u32 saddr;
  } key;

  key.prefixlen = 32;
  key.saddr = ip->saddr;

  // Lookup SRC IP in blocklisted IPs
  __u64 *block_rule_idx = bpf_map_lookup_elem(&blocklist, &key);
  if (block_rule_idx)
  {
    // Matched, increase match counter for matched "rule"
    __u32 index = *(__u32 *)block_rule_idx; // make verifier happy
    return XDP_DROP;
  }

  // Lookup SRC IP in allowlisted IPs
  __u64 *allow_rule_idx = bpf_map_lookup_elem(&allowlist, &key);
  if (allow_rule_idx)
  {
    // Matched, increase match counter for matched "rule"
    __u32 index = *(__u32 *)allow_rule_idx; // make verifier happy
    return XDP_PASS;
  }

  // Structure object to hold the punch data temporarily
  __u32 daddr = ip->daddr;
  __u16 dport = dst_port;
  __u8 protocol = ip->protocol;

  if (lookup_punch_data(daddr, dport, protocol, &punch_list) != 0)
  {
    return XDP_PASS;
  }

  return XDP_DROP;
}