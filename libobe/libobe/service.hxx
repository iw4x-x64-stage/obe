// Copyright (c) the IW4x authors (see the AUTHORS file).
// SPDX-License-Identifier: GPL-3.0-only WITH AdditionRef-IW4x-Exception-1.1

#pragma once

#include <map>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>

#include <libobe/types.hxx>
#include <libobe/utility.hxx>

#include <libobe/lsg-error.hxx>
#include <libobe/bit-parser.hxx>
#include <libobe/bit-serializer.hxx>

#include <libobe/export.hxx>

namespace obe
{
  using boost::asio::awaitable;

  // The lobby service gateway services.
  //
  // Once the client has completed the gateway handshake it sends tasks, each
  // addressed to a service by its id and carrying the operation code and
  // the operation parameters. There are two kinds of tasks. A bit task
  // payload is a type-checked bit buffer:
  //
  // uint8   service id      (raw byte before the buffer)
  // uchar8  operation
  // ...     parameters
  // none    end-of-request marker
  //
  // And the reply is (the task_reply frame):
  //
  // uint64  transaction id
  // uint32  error           (lsg_error)
  // uchar8  operation       (only if no error)
  // ...     results         (only if no error)
  //
  // A byte task payload is raw bytes: the service id, the operation, and
  // the parameters. And its reply (the service_reply frame) is the raw
  // uint64 transaction id followed by the results.
  //
  // Note that the encrypted frames carry the cipher padding at the end of
  // the payload (see frame_parser), so the byte task parameters and results
  // must be self-delimiting (the bit buffers are by construction).
  //
  // The client matches the replies to its tasks in the FIFO order (it
  // doesn't check the transaction id), so every task gets exactly one reply.

  // The identity of the authenticated gateway client.
  //
  struct lsg_identity
  {
    user_id    user;
    title_id   title;
    license_id license;
    uint64_t   connection; // Gateway connection id.

    // The local address of the gateway connection, that is, the address
    // the client reached us at.
    //
    boost::asio::ip::address address;
  };

  // Thrown by the service implementations to reply to the task with an
  // error.
  //
  // The description is formatted from the arguments.
  //
  class task_error: public runtime_error
  {
  public:
    template <formattable_argument... A>
    task_error (lsg_error c, std::format_string<A...> f, A&&... a)
      : runtime_error (std::format (f, std::forward<A> (a)...)), code (c) {}

    lsg_error code;
  };

  // The service interface.
  //
  // The gateway calls one of the handle() functions (depending on the
  // service's kind) for every task addressed to the service. The handler
  // parses the parameters from the input and serializes the results into
  // the output. To reply with an error it throws task_error, in which case
  // the gateway discards whatever was serialized. A bit_parsing exception
  // is replied to with lsg_error::parameter_parse_error. Any other exception
  // closes the connection.
  //
  // When a connection closes, the gateway calls disconnect() on every
  // service so that they can drop the state tied to it (for example, the
  // matchmaking sessions it hosts).
  //
  // The handlers are coroutines that run on the connection's executor and
  // must not block. The gateway, its registry, and the services are confined
  // to the thread that runs the io_context (which therefore must be run by a
  // single thread), so the services keep their state without any
  // synchronization. To scale, run several gateway processes.
  //
  // A handler that waits for something (for example, a database query) does
  // so by co_await'ing it, in which case the gateway serves the other
  // connections in the meantime. The connection's next task is only handled
  // once the handler completes, which keeps the replies in the task order.
  // Note also that the parser and the serializer stay valid across the
  // suspensions but the service state may change (another connection's task
  // may run), so the handler should not hold on to references into it.
  //
  class LIBOBE_SYMEXPORT service
  {
  public:
    enum class kind_type {bit, byte};

    // Return the service's task kind.
    //
    virtual kind_type
    kind () const noexcept = 0;

    // Handle a bit task. The input is positioned after the operation and
    // the output after the echoed operation.
    //
    // The default implementation throws task_error.
    //
    virtual awaitable<void>
    handle (const lsg_identity&,
            uint8_t operation,
            bit_parser& input,
            bit_serializer& output);

    // Handle a byte task. The output is positioned after the transaction
    // id.
    //
    // The default implementation throws task_error.
    //
    virtual awaitable<void>
    handle (const lsg_identity&,
            uint8_t operation,
            span<const uint8_t> input,
            bytes& output);

    // Handle the connection closing. Note that no replies can be sent at
    // this point and that this function is also called for connections
    // that never sent a task to the service.
    //
    // The default implementation does nothing.
    //
    virtual void
    disconnect (const lsg_identity&) noexcept;

    service () = default;

    virtual
    ~service ();

    service (const service&) = delete;
    service& operator= (const service&) = delete;
  };

  // The services by their ids. The services should outlive the gateway.
  //
  using service_map = std::map<uint8_t, reference_wrapper<service>>;
}
