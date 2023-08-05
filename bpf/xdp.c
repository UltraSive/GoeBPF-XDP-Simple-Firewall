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

// BPF Default behavior Map
BPF_MAP_DEF(defaultBehavior) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = 1, // allow / drop
    .max_entries = 16,
};
BPF_MAP_ADD(defaultBehavior);

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
    .value_size = 1, // Small value size (1 byte) since we don't need to store significant data. If we know the key exists we can pass it.
    .max_entries = 1024,
};
BPF_MAP_ADD(punch_list);

// Function to lookup punch data in the punch_list map
__u64 lookup_punch_data(__u32 daddr, __u16 dport, __u8 protocol, struct bpf_map_def *punch_list)
{
  int authorized = 2; // 2 results in no action; 1 to pass; 0 to drop.

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
    __u8 index = *(__u8 *)punch_rule_idx; // make verifier happy
    // Return 1 to indicate a match
    authorized = index;
  }

  return authorized;
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
    // We will leave the dst_port = 0 as it is the placeholder we will use for entries for punching ICMP.
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

  int punchPass = lookup_punch_data(daddr, dport, protocol, &punch_list);

  if (punchPass == 1)
  {
    return XDP_PASS;
  } else if (punchPass == 0)
  {
    return XDP_DROP;
  }

  // Lookup default behavior of IP rules
  struct
  {
    __u32 prefixlen;
    __u32 saddr;
  } dest_key;

  dest_key.prefixlen = 32;
  dest_key.saddr = ip->daddr;

  __u64 *default_behavior_idx = bpf_map_lookup_elem(&defaultBehavior, &dest_key);
  if (default_behavior_idx)
  {
    // Matched, increase match counter for matched "rule"
    __u8 index = *(__u8 *)default_behavior_idx; // make verifier happy
    if (index == 1)
    {
      return XDP_PASS;
    }
  }

  // This accounts for if the default behavior is to drop all not punched or not specified
  return XDP_DROP;
}