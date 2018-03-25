# Feature discovery

During feature discovery, a client figures out the most efficient way to communicate with the server. There are several questions to answer during feature discovery:

 * What name-encoded information gets to the server intact?
   * Is case preserved?
   * Are raw ASCII domain names allowed?
 * What encoding can the server use to talk to the client?
   * Do private-use records work? Can they include raw data?
   * Do TXT records work?
 * What is the maximum outgoing data length?
 * What is the maximum incoming data length?

# Protocol

Each sub-section will describe a different feature-discovery API.

Let `HOSTNAME` be the root domain name of the myodine server. All feature-discovery requests use domain names matching the regular expression `f.*\.HOSTNAME`, where `f` stands for "feature".

## Domain hashing

This API is used to verify that the server received a domain name intact. It can be used to discover what encodings the client can use to talk to the server. For this API, the client sends encoded information in a domain name, and the server sends back a hash of that information. Here's an example:

 * Client: request A record for `fAbCd.HOSTNAME`
 * Server: send A record with the first 4 bytes of the SHA1 hash of `fAbCd.HOSTNAME`.

## Download generation

These calls request a predictable stream of data from the server, and specify which format they'd like to receive the data in.

Data is generated using three seed values: a coefficient, a modulus, and a bias. In particular, the bytes are produced as `(i + bias) * coefficient % modulus`, where i is incrementing starting at 0.

A request is of the following form:

```
`f<encoding>.<len>.<bias>.<coefficient>.<modulus>.<PADDING>.HOSTNAME`
```

Where the fields mean:

 * `<encoding>` - a [download encoding](Encodings.md#download-encodings)
 * `<len>` - number of bytes to generate
 * `<bias>` - the bias term, in base 10
 * `<coefficient>` - the coefficient, in base 10
 * `<modulus>` - the modulus, in base 10
 * `<PADDING>` - an arbitrary sequence of labels to make the request as big as possible
