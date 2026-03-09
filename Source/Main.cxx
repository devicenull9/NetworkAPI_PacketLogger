/**
 * NetworkAPI plugin to print information about packets
 *
 * @license Apache 2.0
 */

#include <iostream>

#include "CCommon.hxx"
#include "NetworkAPI.hxx"
#include "CForwards.hxx"

std::string global_plugin_name = "NetworkAPI_PacketLogger";
std::string global_plugin_version = "1.0.0";
std::string global_plugin_author = "NetworkAPI Development Team";

CForwards_PluginExport CForwards_ForwardResult On_PluginInit()
{
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " On_PluginInit" << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Name: " << global_plugin_name << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Version: " << global_plugin_version << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Author: " << global_plugin_author << std::endl;

    return CForwards_ForwardResult::Forward_Ignored;
}

CForwards_PluginExport CForwards_ForwardResult On_PluginEnd()
{
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " On_PluginEnd" << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Name: " << global_plugin_name << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Version: " << global_plugin_version << std::endl;
    std::cout << CCommon_ConsoleText_Green << "[NetworkAPI:Plugin]" << CCommon_ConsoleText_Default << " - Author: " << global_plugin_author << std::endl;

    return CForwards_ForwardResult::Forward_Ignored;
}

CForwards_PluginExport CForwards_ForwardResult On_PacketReceive_IPv4(NetworkAPI_PacketMetadata *packet_metadata, unsigned char *packet, int *packet_length, unsigned char *data, int *data_length, NetworkAPI_PacketHeader_IPv4 *ipv4_header, NetworkAPI_PacketHeader_TCP *tcp_header, NetworkAPI_PacketHeader_UDP *udp_header, NetworkAPI_PacketHeader_ICMP *icmp_header)
{
    printf("\n");

    printf("On_PacketReceive_IPv4()\n");

    printf("\nIPv4 Header:\n");

    printf("- Version: %d\n", (ipv4_header->version_header_length >> 4));
    printf("- Header Length: %d\n", (ipv4_header->version_header_length & 0x0f) * 4);
    printf("- ToS: %d\n", ipv4_header->tos);
    printf("- Total Length: %d\n", ntohs(ipv4_header->total_length));
    printf("- Identification: %d\n", ntohs(ipv4_header->identification));
    printf("- Flags: %d\n", (ntohs(ipv4_header->flags_offset) >> 0xd));
    printf("- Fragment Offset: %d\n", (ntohs(ipv4_header->flags_offset) & 0x1fff));
    printf("- Time to Live: %d\n", ipv4_header->time_to_live);
    printf("- Protocol: %d\n", ipv4_header->protocol);
    printf("- Checksum: %d\n", ntohs(ipv4_header->checksum));

    char buffer_1[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ipv4_header->source_address, buffer_1, INET_ADDRSTRLEN);

    printf("- Source Address: %s\n", buffer_1);

    char buffer_2[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ipv4_header->destination_address, buffer_2, INET_ADDRSTRLEN);

    printf("- Destination Address: %s\n", buffer_2);

    if (tcp_header != nullptr)
    {
        printf("\nTCP Header:\n");

        printf("- Source Port: %d\n", ntohs(tcp_header->source_port));
        printf("- Destination Port: %d\n", ntohs(tcp_header->destination_port));
        printf("- Sequence Number: %lu\n", ntohl(tcp_header->sequence_number));
        printf("- Acknowledgment Number: %lu\n", ntohl(tcp_header->acknowledgment_number));
        printf("- Header Length: %d\n", (ntohs(tcp_header->offset_reserved_flags) >> 0x0c) * 4);

        printf("- Common Flags: ");

        uint8_t flags = (uint8_t)(ntohs(tcp_header->offset_reserved_flags) & 0x3f);

        if (flags & NetworkAPI_PacketHeader_TCP_Flag_FIN)
            printf("FIN ");

        if (flags & NetworkAPI_PacketHeader_TCP_Flag_SYN)
            printf("SYN ");

        if (flags & NetworkAPI_PacketHeader_TCP_Flag_RST)
            printf("RST ");

        if (flags & NetworkAPI_PacketHeader_TCP_Flag_PSH)
            printf("PSH ");

        if (flags & NetworkAPI_PacketHeader_TCP_Flag_ACK)
            printf("ACK ");

        if (flags & NetworkAPI_PacketHeader_TCP_Flag_URG)
            printf("URG ");

        printf("\n");

        printf("- Window Size: %d\n", ntohs(tcp_header->window_size));
        printf("- Checksum: %d\n", ntohs(tcp_header->checksum));
        printf("- Urgent Pointer: %d\n", ntohs(tcp_header->urgent_pointer));
        printf("- Options: %s\n", ((ntohs(tcp_header->offset_reserved_flags) >> 0x0c) * 4) > 20 ? "true" : "false");
    }

    else if (udp_header != nullptr)
    {
        printf("\nUDP Header:\n");

        printf("- Source Port: %d\n", ntohs(udp_header->source_port));
        printf("- Destination Port: %d\n", ntohs(udp_header->destination_port));
        printf("- Length: %d\n", ntohs(udp_header->length));
        printf("- Checksum: %d\n", ntohs(udp_header->checksum));
    }

    else if (icmp_header != nullptr)
    {
        printf("\nICMP Header:\n");

        printf("- Type: %d\n", icmp_header->type);
        printf("- Code: %d\n", icmp_header->code);
        printf("- Checksum: %d\n", ntohs(icmp_header->checksum));
    }

    if (data != nullptr)
    {
        printf("\nData:\n");

        printf("- Length: %d\n", *data_length);
        printf("- Raw Data:\n");

        for (int iterator = 0; iterator < *data_length; iterator++)
        {
            printf("%02x ", data[iterator]);

            if (iterator == *data_length - 1)
                printf("\n");
        }
    }

    return CForwards_ForwardResult::Forward_Ignored;
}

CForwards_PluginExport CForwards_ForwardResult On_PacketReceive_IPv6(NetworkAPI_PacketMetadata *packet_metadata, unsigned char *packet, int *packet_length, unsigned char *data, int *data_length, NetworkAPI_PacketHeader_IPv6 *ipv6_header, NetworkAPI_PacketHeader_TCP *tcp_header, NetworkAPI_PacketHeader_UDP *udp_header, NetworkAPI_PacketHeader_ICMPv6 *icmpv6_header)
{
    printf("\n");

    printf("On_PacketReceive_IPv6()\n");

    printf("\nIPv6 Header:\n");

    printf("- Version: %d\n", (ntohl(ipv6_header->version_traffic_class_flow_label) >> 28) & 0x0f);
    printf("- Traffic Class: %d\n", (ntohl(ipv6_header->version_traffic_class_flow_label) >> 20) & 0xff);
    printf("- Flow Label: 0x%05x\n", ntohl(ipv6_header->version_traffic_class_flow_label) & 0xfffff);
    printf("- Payload Length: %d\n", ntohs(ipv6_header->payload_length));
    printf("- Next Header: %d\n", ipv6_header->next_header);
    printf("- Hop Limit: %d\n", ipv6_header->hop_limit);

    char buffer_1[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, ipv6_header->source_address, buffer_1, INET6_ADDRSTRLEN);

    printf("- Source Address: %s\n", buffer_1);

    char buffer_2[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, ipv6_header->destination_address, buffer_2, INET6_ADDRSTRLEN);

    printf("- Destination Address: %s\n", buffer_2);

    if (tcp_header != nullptr)
    {
        printf("\nTCP Header:\n");

        printf("- Source Port: %d\n", ntohs(tcp_header->source_port));
        printf("- Destination Port: %d\n", ntohs(tcp_header->destination_port));
        printf("- Sequence Number: %lu\n", ntohl(tcp_header->sequence_number));
        printf("- Acknowledgment Number: %lu\n", ntohl(tcp_header->acknowledgment_number));
        printf("- Header Length: %d\n", (ntohs(tcp_header->offset_reserved_flags) >> 0x0c) * 4);

        printf("- Common Flags: ");

        uint8_t flags = (uint8_t)(ntohs(tcp_header->offset_reserved_flags) & 0x3f);

        if (flags & NetworkAPI_PacketHeader_TCP_Flag_FIN)
            printf("FIN ");

        if (flags & NetworkAPI_PacketHeader_TCP_Flag_SYN)
            printf("SYN ");

        if (flags & NetworkAPI_PacketHeader_TCP_Flag_RST)
            printf("RST ");

        if (flags & NetworkAPI_PacketHeader_TCP_Flag_PSH)
            printf("PSH ");

        if (flags & NetworkAPI_PacketHeader_TCP_Flag_ACK)
            printf("ACK ");

        if (flags & NetworkAPI_PacketHeader_TCP_Flag_URG)
            printf("URG ");

        printf("\n");

        printf("- Window Size: %d\n", ntohs(tcp_header->window_size));
        printf("- Checksum: %d\n", ntohs(tcp_header->checksum));
        printf("- Urgent Pointer: %d\n", ntohs(tcp_header->urgent_pointer));
        printf("- Options: %s\n", ((ntohs(tcp_header->offset_reserved_flags) >> 0x0c) * 4) > 20 ? "true" : "false");
    }

    else if (udp_header != nullptr)
    {
        printf("\nUDP Header:\n");

        printf("- Source Port: %d\n", ntohs(udp_header->source_port));
        printf("- Destination Port: %d\n", ntohs(udp_header->destination_port));
        printf("- Length: %d\n", ntohs(udp_header->length));
        printf("- Checksum: %d\n", ntohs(udp_header->checksum));
    }

    else if (icmpv6_header != nullptr)
    {
        printf("\nICMPv6 Header:\n");

        printf("- Type: %d\n", icmpv6_header->type);
        printf("- Code: %d\n", icmpv6_header->code);
        printf("- Checksum: %d\n", ntohs(icmpv6_header->checksum));
    }

    if (data != nullptr)
    {
        printf("\nData:\n");

        printf("- Length: %d\n", *data_length);
        printf("- Raw Data:\n");

        for (int iterator = 0; iterator < *data_length; iterator++)
        {
            printf("%02x ", data[iterator]);

            if (iterator == *data_length - 1)
                printf("\n");
        }
    }

    return CForwards_ForwardResult::Forward_Ignored;
}
