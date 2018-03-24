# Encodings

There are many different ways to encode information in DNS packets. These different methods will be supported by different pathways.

## Upload encodings

These encodings deal with putting information into domain names. Currently, these are the supported encodings:

 * `b16` - data is encoded as hexadecimal using the characters `0-9a-f`.
 * `b36` - data is encoded in base 36 using the characters `0-9a-z`.
 * `b62` - data is encoded in base 62 using the characters `0-9a-zA-Z`.

## Download encodings

These encodings deal with putting information into DNS responses. The download encoding depends on the requested resource record type. Here are the encodings, divided up by RR:

 * `TXT`
   * `raw` - data is encoded as raw binary data within a TXT record. When 255 bytes are used for a character string, a new character string is started.
 * `PRIVATE (65399)`
   * `raw` - data is encoded as raw data within the RR.
