# Maybenot

Maybenot is a framework for traffic analysis defenses that can be used to hide
patterns in encrypted communication.

Consider encrypted communication protocols such as TLS, QUIC, WireGuard, or Tor.
While the connections are encrypted, *patterns* in the encrypted communication
may still leak information about the underlying plaintext being communicated
over encrypted. Maybenot is a framework for creating defenses that hide such
patterns.

An instance of Maybenot repeatedly takes as *input* one or more *events*
describing the encrypted traffic going over an encrypted channel, and produces
as *output* zero or more *actions*, such as to inject *padding* traffic or
*block* outgoing traffic. One or more *state machines* determine what actions to
take based on events.

## Background
Maybenot is based on the [Circuit Padding Framework of
Tor](https://gitweb.torproject.org/tor.git/plain/doc/HACKING/CircuitPaddingDevelopment.md)
by Mike Perry and George Kadianakis from 2019, which is a generalization of the
[WTF-PAD Website Fingerprinting Defense](https://arxiv.org/pdf/1512.00524.pdf)
design by Juarez et al. from 2016, which in turn is based on the concept of
[Adaptive Padding](https://www.cs.utexas.edu/~shmat/shmat_esorics06.pdf) by
Shmatikov and Wang from 2006.

## More details
See [the specification](https://github.com/maybenot-io/maybenot-spec) for
further details on the framework and machines.