// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <map>
#include <chrono>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/service.hxx>

#include <libobe/export.hxx>

namespace obe
{
  struct bandwidth_settings
  {
    // The size of the test packets (the UDP payload). It should fit into the
    // path MTU since the fragments of a lost one are lost for nothing.
    //
    uint32_t packet_size = 1200;

    // The number of test packets sent in each direction, which together with
    // their size and the durations below determines the rate at which they
    // are sent (about 1.9Mbit/s by default). The measured rate cannot exceed
    // it, so it should be above the highest rate the title cares about
    // (2Mbit/s).
    //
    uint32_t packet_count = 400;

    // The time the client waits after the test is accepted before sending.
    //
    std::chrono::milliseconds start_delay {0};

    // The time over which the client sends its packets.
    //
    std::chrono::milliseconds upload_duration {2000};

    // The time over which we send our packets.
    //
    std::chrono::milliseconds download_duration {2000};

    // The time the client waits for our first packet once it is done
    // sending. If the download is longer than the upload, the client also
    // waits for the difference.
    //
    std::chrono::milliseconds download_timeout {5000};

    // The time the client waits for more packets after the last one, in
    // addition to the time it has been receiving them.
    //
    std::chrono::milliseconds download_linger {500};

    // The time we wait for more packets after the last one once the client
    // asks for the results (its last packets may still be on their way).
    //
    std::chrono::milliseconds upload_linger {250};

    // The address and port the clients send their packets to. If
    // unspecified, then they are the address the client reached the gateway
    // at and the port we are bound to (which means the test is only
    // possible over IPv4). Specify them if we are behind NAT or bound to
    // another address.
    //
    optional<boost::asio::ip::address_v4> public_address;
    uint16_t                              public_port = 0;

    // The most tests in progress, each taking up packet_size bytes.
    //
    size_t max_tests = 256;
  };

  // The bandwidth test service (bdBandwidthTest, service 18).
  //
  // This is a byte service whose test packets are exchanged over UDP. The
  // client requests a test with operation 1 and the following parameters:
  //
  // uint8  0         (request)
  // uint8  test type (0 upload, 1 upload and download)
  //
  // Followed by 14 unspecified bytes. If accepted, the reply is:
  //
  // uint8    0
  // uint32   packet size
  // uint32   packet count
  // uint32   start delay       (milliseconds)
  // uint32   upload duration   (milliseconds)
  // uint32   download timeout  (milliseconds)
  // uint32   download duration (milliseconds)
  // uint32   download linger   (milliseconds)
  // uint16   port
  // uint8[4] IPv4 address      (in the network byte order)
  // uint8[8] token
  //
  // Where all the integers are little-endian. The client then sends the
  // packets to the address and port, spreading them over the upload
  // duration, each as follows (with the rest of the packet random):
  //
  // uint32   sequence number   (from 0)
  // uint8[8] token
  //
  // For the download test, once it is done sending, the client expects the
  // packets of the same form from the same address and port, and measures
  // the rate. Either way it then finalizes the test, also with operation 1:
  //
  // uint8     1      (finalize)
  // uint32[5] download results (all 0 if only the upload is tested)
  //
  // And if accepted, the reply is uint8 0 followed by the upload results.
  // The results are:
  //
  // uint32 bytes received (including 8 bytes of UDP header per packet)
  // uint32 period         (milliseconds, at least 1)
  // uint32 average sequence number
  // uint32 lowest sequence number
  // uint32 highest sequence number
  //
  // A rejected request or finalization gets the reply of uint8 1 followed
  // by the uint16 error code, which the client only logs.
  //
  // The client runs the upload test once, right after connecting, and only
  // uses the upload rate (bytes received over the period): to decide
  // whether it may host a lobby of a given size and to nominate itself as
  // the host on host migration. If the test fails, then the client keeps the
  // default of 768000 bits per second, which is above what it requires for
  // the largest lobby (580000 for 18 players), and never retries.
  //
  // We measure the period from the first to the last packet received, so
  // we count the bytes of the packets after the first (the client counts
  // all of them on download, which overestimates the rate by a packet). If
  // fewer than two packets arrive, then we reject the finalization (with
  // bandwidth_test_socket_error) so that the client keeps the default rather
  // than finding out it can't host: such a test says more about the path to
  // us than about the client's bandwidth.
  //
  // The tests live as long as the connections that requested them: a new
  // request replaces the connection's test and the finalization ends it.
  // The packets are matched to the tests by the token, which is random so
  // that only the client knows it, and the download packets are sent to
  // where the upload packets came from.
  //
  // Like the gateway, the service must be run by a single thread and the
  // handlers of its io_context must be destroyed before it is (see
  // lsg_server).
  //
  class LIBOBE_SYMEXPORT bandwidth_service: public service
  {
  public:
    using udp = boost::asio::ip::udp;

    // Bind to the endpoint. Throw boost::system::system_error on failure.
    //
    // The packet size must be at least 12 (the sequence number and the
    // token) and fit into a UDP datagram, the packet count and the upload
    // and download durations and download timeout must be positive, and the
    // durations must fit into uint32 milliseconds.
    //
    bandwidth_service (const boost::asio::any_io_executor&,
                       const udp::endpoint&,
                       bandwidth_settings = {});

    // Return the local endpoint (useful if bound to port 0).
    //
    udp::endpoint
    endpoint () const;

    // Receive the test packets until the socket is closed or the operation
    // is cancelled.
    //
    awaitable<void>
    run ();

    // Stop receiving the test packets.
    //
    void
    close ();

    virtual kind_type
    kind () const noexcept override {return kind_type::byte;}

    virtual awaitable<void>
    handle (const lsg_identity&,
            uint8_t operation,
            span<const uint8_t>,
            bytes&) override;

    virtual void
    disconnect (const lsg_identity&) noexcept override;

  private:
    using token_type = array<uint8_t, 8>;
    using steady = std::chrono::steady_clock;

    struct test
    {
      uint64_t connection;
      bool     download;

      // The packet we send, with the token and the random rest filled in.
      //
      bytes packet;

      // Where the upload packets come from (unknown until the first one).
      //
      optional<udp::endpoint> client;

      // The upload statistics.
      //
      uint32_t           packets  = 0;
      uint64_t           received = 0; // Bytes after the first packet.
      uint64_t           total    = 0; // Of the sequence numbers.
      uint32_t           lowest   = 0;
      uint32_t           highest  = 0;
      steady::time_point first;
      steady::time_point last;
      bool               complete = false; // Got the last packet.

      // Cancelled once the last packet arrives (never expires otherwise).
      //
      unique_ptr<boost::asio::steady_timer> completion;
    };

    // Drop the connection's test, if any.
    //
    void
    drop (uint64_t connection) noexcept;

    awaitable<void>
    request (const lsg_identity&, span<const uint8_t>, bytes&);

    awaitable<void>
    finalize (const lsg_identity&, span<const uint8_t>, bytes&);

    // Wait until the test's upload is complete, the test is gone, or the
    // deadline.
    //
    awaitable<void>
    wait (const token_type&, steady::time_point deadline);

    // Account for the received packet.
    //
    void
    receive (span<const uint8_t>, const udp::endpoint&);

    // Send the download packets of the test once its upload is complete.
    //
    awaitable<void>
    send (token_type);

    udp::socket                    socket_;
    const bandwidth_settings       settings_;
    std::map<token_type, test>     tests_;
    std::map<uint64_t, token_type> connections_; // Connection's test.
  };
}
