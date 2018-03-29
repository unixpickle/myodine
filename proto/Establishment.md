# Establishment

During establishment, the client sends the server proof that it knows a password. It also sends information about a remote client for the server to proxy to.

# Protocol

Let `HOSTNAME` be the root domain name of the myodine server.

## Request

The establishment request has a domain name of the form:

```
e<response-encoding>.<mtu>.<name-encoding>.<query-window>.<response-window>.<proof>.<port>.<host>.HOSTNAME
```

Here is a breakdown of each field:

 * `<response-encoding>` - a string representing the encoding to use for responses. The request RR type tells the server something about the encoding, but it leaves out specific information (e.g. the characters that `TXT` supports). For now, the only supported value is `raw`.
 * `<mtu>` - a base-10 number indicating the maximum number of bytes the server may send in a single response payload.
 * `<name-encoding>` - a string representing the encoding used to put data into domain names. See [Upload encodings](Encodings.md#upload-encodings) for more.
 * `<query-window>` - the client's outgoing window size.
 * `<response-window>` - the server's outgoing window size.
 * `<proof>` - a hexadecimal value storing the first 8 bytes of the SHA1 hash of `<password><time><password>`, where `time` is the current epoch time in seconds encoded as a decimal string. The server should not accept proofs for times that are off by more than a minute or so.
 * `<port>` - the TCP port to proxy to.
 * `<host>` - the host to proxy to.

## Response

The response to an establishment request contains raw data in the requested encoding. For a successful request, here are the fields:

 * `status: u8` - 0 for a successful connection.
 * `session_id: u16` - a value that uniquely identifies this session.
 * `seq_num: u32` - a random value in the range `[0, 2^32)`. This is used as the initial sequence number for both the incoming and outgoing streams.

For a failed request, here are the fields:

 * `status: u8` - 1, indicating a failure.
 * `message: variable` - a string encoding the error message.
