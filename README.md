# pyikev2
Python implementation of the IKEv2 protocol. It provides:

* Complete IKEv2 message parsing and generation.
* Support of PSK and RSA (raw keys) authentication
* Support for creating CHILD_SAs using the Linux XFRM interface
* Logging of all the message exchanges for easy inspection.
* Single-thread model, with no locks for easier understanding.
* Small codebase.

The intent of this implementation is not to provide an outstanding performance or security, but to serve as a didactic and support tool for learning and/or research projects.

Its design allows to create scripts to manually test other implementations (see test_ikesa.py and test_ikesacontroller.py for examples of how IKEv2 exchanges can be processed)

# How to run the examples
First, edit alice.yaml and bob.yaml to adjust the IP addresses you want to use. 

Then execute in "alice":
```bash
python3 pyikev2.py -c alice.yaml
```   
And in bob:
```bash
python3 pyikev2.py -c bob.yaml
```   
Finally, in a different terminal, execute in "alice":
```
telnet bob
```
You should see something similar to the following (on "alice"):
```bash
[2020-01-31 15:51:41.122] [INFO   ] Listening from [172.50.1.2]:500
[2020-01-31 15:51:41.122] [INFO   ] Listening from [172.100.1.2]:500
[2020-01-31 15:51:41.122] [INFO   ] Listening control events on [127.0.0.1]:9999
[2020-01-31 15:51:41.122] [INFO   ] Listening XFRM events.
[2020-01-31 15:51:43.530] [INFO   ] Starting the creation of IKE SA with SPI=cbfc7b0c1fc870fc. Count=1
[2020-01-31 15:51:43.530] [INFO   ] IKE_SA: cbfc7b0c1fc870fc. Received acquire from policy with index=439480
[2020-01-31 15:51:43.657] [INFO   ] IKE_SA: cbfc7b0c1fc870fc. Sent IKE_SA_INIT request (1278 bytes) to 172.50.1.3 [SA, NONCE, KE, VENDOR]
[2020-01-31 15:51:43.887] [INFO   ] IKE_SA: cbfc7b0c1fc870fc. Received IKE_SA_INIT response (1289 bytes) from 172.50.1.3 [SA, NONCE, KE, VENDOR]
[2020-01-31 15:51:44.111] [INFO   ] IKE_SA: cbfc7b0c1fc870fc. Sent IKE_AUTH request (1440 bytes) to 172.50.1.3 [TSi, TSr, SA, KE, N(USE_TRANSPORT_MODE), IDi, AUTH]
[2020-01-31 15:51:44.344] [INFO   ] IKE_SA: cbfc7b0c1fc870fc. Received IKE_AUTH response (1472 bytes) from 172.50.1.3 [NONCE, N(USE_TRANSPORT_MODE), KE, SA, TSi, TSr, IDr, AUTH]
[2020-01-31 15:51:44.461] [INFO   ] IKE_SA: cbfc7b0c1fc870fc. Created CHILD_SA (658e3eec, 8d46ebca)
```

