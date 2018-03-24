# Overview

Myodine uses a protocol that I call "myo". The myo protocol consists of three phases:

 * [Feature discovery](FeatureDiscovery.md) - finding MTUs, available encodings, etc.
 * [Establishment](Establishment.md) - authentication & session creation
 * [Transfer](Transfer.md) - a bidirectional virtual circuit

All of these phases use various [encodings](Encodings.md) &mdash; ways of putting raw binary data into DNS packets.
