# pyikev2
Python implementation of the IKEv2 protocol. It provides:

* Complete IKEv2 message parsing and generation.
* Support of PSK authentication
* Support for creating CHILD_SAs using the Linux XFRM interface
* Logging of all the message exchanges for easy inspection.
* Single threaded model, with no locks for easier understanding.
* Small codebase.

The intent of this implementation is not to provide an outstanding performance or security, but to serve as a didactic and support tool for learning and/or research projects.

