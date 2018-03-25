# Transfer

Once a connection has been established, data is sent back and forth in a reliable, sequential stream. This is done using a bidirectional "windowing with retransmission" protocol, *WWR*.

# WWR

The windowing with retransmission (WWR) protocol is a simple way for a DNS client and a DNS server to communicate in a reliable, bidirectional way with high bandwidth. It supports multiple concurrent DNS requests, retransmission, polling, etc.

## Exposed interface

WWR exposes a TCP-like interface to the application. In particular, it gives a reliable bidirectional binary stream. It can make use of buffering, meaning that applications should write large chunks at a time so that those chunks can be split up and sent in parallel.

## Operational overview

For this section, "stream" is used to refer to a unidirectional stream of data. This section gives an overview of how streams operate in a reliable manner.

The outgoing data on a stream is split up into chunks, each with a sequence ID. Chunks are created as data is queued up to be sent on the stream. Potentially, some kind of buffering mechanism can be used to make sure that chunks are as close as possible to the MTU.

We define a few terms here:

 * *Sent sequence* - (for the sender) the longest sequence of chunks, starting at the first chunk, such that all chunks in the sequence have been acknowledged by the receiver.
 * *Received sequence* - (for the receiver) the longest sequence of chunks, starting at the first chunk, such that all chunks have been received.
 * *Sender window* - a sequence of chunks, starting directly after the start of the sent sequence, consisting of at most *window size* chunks.
 * *Receiver window* - the analog of sender window for the receiver.
 * *Window size* - the maximum number of chunks in the window.

The goal of the sender is to provide the receiver with chunks that it has not yet seen. The receiver's job is to acknowledge chunks that it has seen. Since in practice there are streams going in both directions, every packet contains information for both a receiver and a sender.

Every packet sent over WWR has this overall structure:

 * Acknowledgement - describes the receiver's current state
   * Window start - the ID of the first chunk after the received sequence.
   * Window mask - a bitmask indicating which chunks in the current window have been seen. containing  bits, where 1 indicates that the chunk in the window has been received. The first bit will never be 1, since then the window start would simply increase.
 * Chunk - a chunk to be sent over the stream. This is optional, since no data may be pending.
   * Sequence ID
   * Data

Whenever a sender receives an acknowledgement, it can update its state accordingly. It may be able to expand its sent sequence, or it may simply note that certain chunks in the sender window have been acknowledged. Acknowledgements should be dealt with as an OR operation. Once a chunk has been acknowledged, it cannot be un-acknowledged. This deals with the fact that acknowledgements may be received out of order.

## Motivation

WWR balances parallelism with sequential transmission. Since WWR exposes a virtual circuit abstraction, a receiving application using WWR cannot do anything until it receives the chunk of data which immediately follows the received sequence. However, it would still be nice to leverage some amount of parallel transmission to overcome latency issues.

The windowing mechanism in WWR provides some amount of parallelism while still prioritizing data that immediately follows the received sequence. It allows the sender to send out multiple chunks at once, but it does not allow the sender to get too eager with its transmissions until the next chunk has been sent.

## Caching & Retransmission

One common issue with DNS tunnels is that a resolver may cache responses. Thus, if a DNS client wants to send two messages to a DNS server, it must ensure that those messages arrive in unequal queries. Conversely, if a DNS client does not care if a DNS server receives a message multiple times (as long as it receives it once), then the client can retransmit the same query.

The WWR protocol is setup so that incoming packets are idempotent--receiving the same packet multiple times has no effect.

Generally, different chunks will always be sent in unequal queries. This is due to the sequence number, which continually increments for every chunk. The sequence number may eventually wrap, but it will do so infrequently enough that the DNS resolver's cache will have no conceivable way of remembering such old queries. There is of course a wrinkle here: what if the DNS resolver stops changing its cache once the cache is full, and thus memorizes the first few queries? In practice, though, this probably will not be an issue.

# WWR over DNS

This section describes how WWR can be implemented in practice over DNS.

## Protocol

Let `HOSTNAME` be the root domain name of the myodine server. All data transfer queries are for domains matching the regular expression `(t|p).*\.HOSTNAME`, where `t` stands for "transmission" and `p` stands for "poll". The variable contents of the domain name is used to encode binary data.

The binary data for `t` queries is structured as follows:

 * `session_id: u16` - the established session ID.
 * `window_start: u32` - the ID of the first chunk after the received sequence.
 * `window_mask: <variable>` - a bitmask indicating which window chunks have been received. Contains at least `window_size - 1` bits. Does not include the first chunk, since the window start would be incremented if the first chunk of the window had been received.
 * `chunk_seq: u32` - the sent chunk's sequence number.
 * `chunk_data: <variable>` - the sent chunk's contents.

The binary data for `p` queries is structured as follows:

 * `session_id: u16` - the established session ID.
 * `window_start: u32` - same as for `t` queries.
 * `window_mask: <variable>` - same as for `t` queries.
 * `random: u64` - a random value; prevents caching. This way, if the server has no data to receive and the client has no data to send, the client can continually poll for data and get uncached responses.

The body of responses are structured the same way as those for `t` queries, excluding the `session_id` field. If there is no data to be sent in the response, then the `chunk_seq` and `chunk_data` fields are omitted.

## Parallelism

In order to increase performance, clients can make multiple DNS queries concurrently. One possible way to do this from the client's perspective is as follows:

 * There are N "slots" for concurrent DNS queries.
 * Every time a slot becomes free, send the next chunk and current acknowledgement state.
 * Every time a new chunk is added to the sending window, if there is a free slot, send the chunk.
 * Every time a query takes more than T seconds to get a response, free its slot.
 * Every time a query gets a response, free its slot.
 * If all slots have been free for more than P seconds, send a poll query.

The server can operate in a way which is agnostic to the client's parallelism. For every query, it can simply send the next chunk in a round-robin fashion.
