#include <iostream>
#include <list>
#include <cmath>
#include <sstream>
#include <memory>
#include <chrono>

#include "sha1.hpp"

/* Header-only libraries */
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>

#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

//#define DEBUG

using namespace boost::multiprecision;

class Node;

enum class Timeout
{
    /* The time (in seconds) after which a key / value pair expires;
     * this is a time-to-live (TTL) from the original publication date. */
    EXPIRE = 86400,
    /* The time (in seconds) after which an otherwise unaccessed bucket must be refreshed. */
    REFRESH = 3600,
    /* The interval (in seconds) between Kademlia replication events, when a node is requered to publish its entire database. */
    REPLICATE = 3600,
    /* The time (in seconds) after which the original publisher must republish a key / value pair. */
    REPUBLISH = 86400
};

class Bucket
{
    // List of references to nodes (contacts).
    std::list<uint256_t> contacts_;

    /* Maximum number of contacts stored in a bucket;
     * this is normally 20. */
    const uint8_t k_;

    /* Covered distance of nodes for this bucket. */
    const uint256_t covered_distance_from_;
    const uint256_t covered_distance_to_;
public:
    explicit Bucket(const uint256_t& covered_distance_from, const uint256_t& covered_distance_to) :
        k_                      { 20                    },
        covered_distance_from_  { covered_distance_from },
        covered_distance_to_    { covered_distance_to   }
    {

    }

    void Put(const uint256_t& node_id)
    {
        if(contacts_.size() < k_)
        {
            contacts_.push_back(node_id);
        }
        else
        {
            throw std::out_of_range("Bucket size must be less or equal " + std::to_string(k_));
        }
    }

    const uint256_t& CoveredDistanceFrom() const
    {
        return covered_distance_from_;
    }

    const uint256_t& CoveredDistanceTo() const
    {
        return covered_distance_to_;
    }

    friend std::ostream& operator<<(std::ostream& os, const Bucket& bucket)
    {
        for (auto bucket: bucket.contacts_)
        {
            os << bucket << "\n";
        }

        return os;
    }
};

class BucketList
{
    enum { SHA1_HASH_SIZE = 160 };
    std::list<Bucket> bucket_list_;
public:
    explicit BucketList()
    {
        for(auto index = 0; index < SHA1_HASH_SIZE; ++index)
        {
            auto covered_distance_from = pow(cpp_dec_float_100(2), cpp_dec_float_100(index));
            auto covered_distance_to = pow(cpp_dec_float_100(2), cpp_dec_float_100(index + 1));

            Bucket bucket(static_cast<uint256_t>(covered_distance_from),
                          static_cast<uint256_t>(covered_distance_to));

            bucket_list_.push_back(bucket);
        }

#ifdef DEBUG
        std::cout << "Level\tIDs\tCovered Distance\n";
        auto index = 0;

        for(auto bucket: bucket_list_)
        {
            std::cout << "#"    << index++
                      << "\t"   << rand() % 20
                      << "\t["  << bucket.CoveredDistanceFrom()
                      << ", "   << bucket.CoveredDistanceTo()
                      << ")"
                      << std::endl;
        }
#endif
    }

    void Push(const Node& other_node, const uint256_t& distance)
    {
        cpp_dec_float_100 d(distance);
        d += 4;

        std::cout << "Level: " << static_cast<uint32_t>(log2(d)) << " -- " << log2(d) << std::endl;
    }
};

class Node
{
    /* Size in bits of the key used to identity node and store and retreive data;
     * in basic Kademlia this is 160, the length of an SHA1 digest (hash).
     * First 96 bits will not be used. */
    const uint256_t id_;

    /* Each node keeps a list of references to nodes (contacts) of distance between 2 ^ i and 2 ^ (i + 1) for i = 1 to i = N;
     * 0 <= i < 160. */
    std::unique_ptr<BucketList> bucket_list_;

    struct sockaddr_storage address_;
    uint32_t addres_length_;

    /* Time of last message received. */
    std::chrono::time_point<std::chrono::system_clock> last_message_time_;

    /* Time of last correct reply received. */
    std::chrono::time_point<std::chrono::system_clock> last_reply_time_;

    /* Time of last request. */
    std::chrono::time_point<std::chrono::system_clock> last_pinged_time_;

    /* How many requests has been sent since last reply. */
    uint32_t last_pinged_;

    // TODO: Generation SHA1 from MAC-address/es.
    uint256_t GenerateID(const char* raw_data)
    {
        SHA1 checksum;
        checksum.update(raw_data);

        std::stringstream ss;
        ss << std::hex << checksum.final() << std::endl;

        uint256_t temp_id;
        ss >> temp_id;

        return temp_id;
    }
public:
    // TODO: Generation SHA1 from MAC-address/es.
    explicit Node(const char* raw_data) :
        id_                 { GenerateID(raw_data)             },
        bucket_list_        { new BucketList                   },
        last_message_time_  { std::chrono::system_clock::now() },
        last_reply_time_    { std::chrono::system_clock::now() },
        last_pinged_time_   { std::chrono::system_clock::now() }
    {

    }

    /* Distance between ID1 and ID2: ID1 XOR ID2. */
    uint256_t CalculateDistance(const Node& other_node) const
    {
        return id_ ^ other_node.GetID();
    }

    const uint256_t& GetID() const
    {
        return id_;
    }

    void AddToList(const Node& other_node)
    {
        auto distance { CalculateDistance(other_node) };
        bucket_list_.get()->Push(other_node, distance);
    }

    friend std::ostream& operator<<(std::ostream& os, const Node& node)
    {
        return os << node.id_;
    }
};

int main()
{
    Node node1 { "The quick brown fox jumps over the lazy dog" };
    Node node2 { "The quick brown fox jumps over the lazy dog" };

    node1.AddToList(node2);

    //std::cout << "[Node 1]:\t"      << std::hex << node1.GetID()
    //          << "\n[Node 2]:\t"    << std::hex << node2.GetID()
    //          << "\n[Distance]:\t"  << distance
    //          << std::endl;
}
