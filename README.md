# pyikev2
Python implementation of the IKEv2 protocol. It provides:

* Complete IKEv2 message parsing and generation.
* Support of PSK and RSA (raw keys) authentication
* Support for IPv4 and IPv6
* Support for creating CHILD_SAs using the Linux XFRM interface
* Logging of all the message exchanges for easy inspection.
* Single-thread model, with no locks for easier understanding.
* Small codebase.

The intent of this implementation is not to provide an outstanding performance or security, but to serve as a didactic and support tool for learning and/or research projects.

Its design allows creating scripts to manually test other implementations (see test_ikesa.py and test_ikesacontroller.py for examples of how IKEv2 exchanges can be processed)

# How to run the examples
A `docker-compose` and `Dockerfile` files are provided to provide a ready-to-use testing environment:

In order to prepare it, run:
```bash
docker-compose up --build -d
```
That will create the images and run the containers (`alice` and `bob`) in the background.
You can connect to their log console by using `docker-compose logs`.

In order to start the IKEv2 exchange, you must create traffic that is protected by the configuration. In this case, you must send traffic to Bob's port 23 (telnet). You can easily do that by executing:
```bash
docker-compose exec alice ncat bob 23
```
This command creates a TCP connection to port 23 and keeps attached to the console. You should see any line you type echoed by the server.

```bash
docker-compose exec alice ncat bob 23
Hello, this is a test
Hello, this is a test
This is working
This is working
```

In addtion, you should see something similar to the following when checking Alice's log:
```text
Attaching to pyikev2_alice_1
alice_1  | [2020-02-18 11:44:30.588] [INFO   ] Listening from [172.50.1.2]:500
alice_1  | [2020-02-18 11:44:30.589] [INFO   ] Listening control events on [127.0.0.1]:9999
alice_1  | [2020-02-18 11:44:30.589] [INFO   ] Listening XFRM events.
alice_1  | [2020-02-18 11:44:41.500] [INFO   ] Starting the creation of IKE SA=bdea01b704f08e9e. Count=1
alice_1  | [2020-02-18 11:44:41.500] [INFO   ] IKE_SA: bdea01b704f08e9e. Received acquire from policy with index=34821
alice_1  | [2020-02-18 11:44:41.501] [INFO   ] IKE_SA: bdea01b704f08e9e. Sent IKE_SA_INIT request (300 bytes) to 172.50.1.3 [SA, NONCE, KE, VENDOR]
alice_1  | [2020-02-18 11:44:41.504] [INFO   ] IKE_SA: bdea01b704f08e9e. Received IKE_SA_INIT response (416 bytes) from 172.50.1.3 [SA, NONCE, KE, VENDOR]
alice_1  | [2020-02-18 11:44:41.506] [INFO   ] IKE_SA: bdea01b704f08e9e. Sent IKE_AUTH request (448 bytes) to 172.50.1.3 [TSi, TSr, SA, KE, IDi, AUTH]
alice_1  | [2020-02-18 11:44:41.509] [INFO   ] IKE_SA: bdea01b704f08e9e. Received IKE_AUTH response (448 bytes) from 172.50.1.3 [NONCE, SA, TSi, TSr, IDr, AUTH]
alice_1  | [2020-02-18 11:44:41.510] [INFO   ] IKE_SA: bdea01b704f08e9e. Created CHILD_SA (afb32cca, 5a1740fe)
```

If you want to see more detailed output, add the `EXTRA_PARAMS: -v` to Alice's and Bob's environment in the `docker-compose.yml` file. You should see something similar to the following when checking Alice's log:
```text
Attaching to pyikev2_alice_1
alice_1  | [2020-02-18 11:46:01.008] [INFO   ] Listening from [172.50.1.2]:500
alice_1  | [2020-02-18 11:46:01.008] [INFO   ] Listening control events on [127.0.0.1]:9999
alice_1  | [2020-02-18 11:46:01.008] [INFO   ] Listening XFRM events.
alice_1  | [2020-02-18 11:46:07.004] [INFO   ] Listening from [172.50.1.2]:500
alice_1  | [2020-02-18 11:46:07.004] [INFO   ] Listening control events on [127.0.0.1]:9999
alice_1  | [2020-02-18 11:46:07.004] [INFO   ] Listening XFRM events.
alice_1  | [2020-02-18 11:46:11.014] [DEBUG  ] Received acquire for 172.50.1.3
alice_1  | [2020-02-18 11:46:11.015] [INFO   ] Starting the creation of IKE SA=4032e4155ba9ceb6. Count=1
alice_1  | [2020-02-18 11:46:11.015] [INFO   ] IKE_SA: 4032e4155ba9ceb6. Received acquire from policy with index=197423
alice_1  | [2020-02-18 11:46:11.018] [INFO   ] IKE_SA: 4032e4155ba9ceb6. Sent IKE_SA_INIT request (485 bytes) to 172.50.1.3 [SA, NONCE, KE, VENDOR]
alice_1  | [2020-02-18 11:46:11.019] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. {
alice_1  |   "spi_i": "4032e4155ba9ceb6",
alice_1  |   "spi_r": "0000000000000000",
alice_1  |   "major": 2,
alice_1  |   "minor": 0,
alice_1  |   "exchange_type": "IKE_SA_INIT",
alice_1  |   "is_request": true,
alice_1  |   "is_response": false,
alice_1  |   "can_use_higher_version": false,
alice_1  |   "is_initiator": true,
alice_1  |   "is_responder": false,
alice_1  |   "message_id": 0,
alice_1  |   "payloads": [
alice_1  |     {
alice_1  |       "type": "SA",
alice_1  |       "critical": false,
alice_1  |       "proposals": [
alice_1  |         {
alice_1  |           "num": 1,
alice_1  |           "protocol_id": "IKE",
alice_1  |           "spi": "4032e4155ba9ceb6",
alice_1  |           "transforms": [
alice_1  |             {
alice_1  |               "type": "ENCR",
alice_1  |               "id": "ENCR_AES_CBC",
alice_1  |               "keylen": 256
alice_1  |             },
alice_1  |             {
alice_1  |               "type": "INTEG",
alice_1  |               "id": "AUTH_HMAC_SHA2_512_256"
alice_1  |             },
alice_1  |             {
alice_1  |               "type": "PRF",
alice_1  |               "id": "PRF_HMAC_SHA2_512"
alice_1  |             },
alice_1  |             {
alice_1  |               "type": "DH",
alice_1  |               "id": "DH_21"
alice_1  |             }
alice_1  |           ]
alice_1  |         }
alice_1  |       ]
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "NONCE",
alice_1  |       "critical": false,
alice_1  |       "nonce": "e2ee65f6ff6df7db555dd91244c893f6f8b7821a7e6059f8f9240447c2bf415d5ed8a02c613ae88411d11a06b3142168b5bb531b1f8d3c7ce2363a3fddb678ee0a48cafe2da2d6ebe7a623139f936e452800869e608edf76813b3f57da9c396ef80a96a5c8e89aab84a8ae3788ceb68a7084bbac37f205bd93ee393b6905f26cb0661b90bdd93ae4daf5b00bfd5fb3a735f5eb1d846c43208eb48662ab361c819003a02a7a238a0ea2cab55b66f306b9c48ec1ddf9bfe0b5b00a901053f1d24923751fe8358eeff17fa23fe1be8be36fc082a98a830666a7c1a012d2252930190d32a799bf5737e6661004437c0bdd8da63e"
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "KE",
alice_1  |       "critical": false,
alice_1  |       "dh_group": 21,
alice_1  |       "ke_data": "00900a998f14043b8058f0464c21d01e6f3d24631c3c1fa60e6c809708528dd5ab388e55cdc634dde0640c5ddacecc2fdac8703fabebbfcc175fdd40f737b739974b0171eef05e51e157815652b42acfdc97f5d2256503cebaf1388c80ab6d2657ca28f8188a0c265e7b7ca5538eb966654d8081af70779211bd59c5c8c7284751b09ac3"
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "VENDOR",
alice_1  |       "critical": false,
alice_1  |       "vendor_id": "pyikev2-0.1"
alice_1  |     }
alice_1  |   ],
alice_1  |   "encrypted_payloads": []
alice_1  | }
alice_1  | [2020-02-18 11:46:11.030] [INFO   ] IKE_SA: 4032e4155ba9ceb6. Received IKE_SA_INIT response (345 bytes) from 172.50.1.3 [SA, NONCE, KE, VENDOR]
alice_1  | [2020-02-18 11:46:11.030] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. {
alice_1  |   "spi_i": "4032e4155ba9ceb6",
alice_1  |   "spi_r": "0e37fed63a0db92c",
alice_1  |   "major": 2,
alice_1  |   "minor": 0,
alice_1  |   "exchange_type": "IKE_SA_INIT",
alice_1  |   "is_request": false,
alice_1  |   "is_response": true,
alice_1  |   "can_use_higher_version": false,
alice_1  |   "is_initiator": false,
alice_1  |   "is_responder": true,
alice_1  |   "message_id": 0,
alice_1  |   "payloads": [
alice_1  |     {
alice_1  |       "type": "SA",
alice_1  |       "critical": false,
alice_1  |       "proposals": [
alice_1  |         {
alice_1  |           "num": 1,
alice_1  |           "protocol_id": "IKE",
alice_1  |           "spi": "0e37fed63a0db92c",
alice_1  |           "transforms": [
alice_1  |             {
alice_1  |               "type": "ENCR",
alice_1  |               "id": "ENCR_AES_CBC",
alice_1  |               "keylen": 256
alice_1  |             },
alice_1  |             {
alice_1  |               "type": "INTEG",
alice_1  |               "id": "AUTH_HMAC_SHA2_512_256"
alice_1  |             },
alice_1  |             {
alice_1  |               "type": "PRF",
alice_1  |               "id": "PRF_HMAC_SHA2_512"
alice_1  |             },
alice_1  |             {
alice_1  |               "type": "DH",
alice_1  |               "id": "DH_21"
alice_1  |             }
alice_1  |           ]
alice_1  |         }
alice_1  |       ]
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "NONCE",
alice_1  |       "critical": false,
alice_1  |       "nonce": "73958401f6c73a1deab21d180778b769c83b3dd124bbc52d8d61cab97bb181b402b87bf8b1db8229ed5fa60cb3095f2a9eb8dcb825cd9118459eeb6324995f1193fc9160d52ca0700b6377ca5191a03c6f1a2bc7308b0c4687ab25f077deeb5b10fe652b6016"
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "KE",
alice_1  |       "critical": false,
alice_1  |       "dh_group": 21,
alice_1  |       "ke_data": "0069f3ecbab20b1c55c727d12d05bd4dbeb3b47828a470cfbf193d07fc359d47f256a7ceeb3c47b6caedc23ea98e3fd94d28629aeac9eb46609ce36316190592e3d801f37008f0fd2c9397946779320952f316dbfa23524e49253a47cd76f088256a45b10c4e2747c2fe69ccaae0ed87ffd4f4554a6fb1ac12d2666ac5d29a97a33ed1b1"
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "VENDOR",
alice_1  |       "critical": false,
alice_1  |       "vendor_id": "pyikev2-0.1"
alice_1  |     }
alice_1  |   ],
alice_1  |   "encrypted_payloads": []
alice_1  | }
alice_1  | [2020-02-18 11:46:11.034] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated DH shared secret: 0154df0d870a8cb9e2200d710ad95b0a109e44d632789576912ec9df8d836f050a94033b1b36923425f384e80893d9b69245eae9c2e6fb435019da613505b3a2a7d6
alice_1  | [2020-02-18 11:46:11.035] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated SKEYSEED: 53b406f41cad5c1b82641e93fdfaa19f3f8e711fba1b1355ca36224a41062b2797b7da5439a5f6905062367288417885dac4c8a1dc522abaa12f23dacacdfead
alice_1  | [2020-02-18 11:46:11.035] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated sk_d: 42dd0c478032954fffa1cf1a4bb9f0d6568769ae245a8cceff47b91e6a323bb4ffa770afde73093d68976466e9d63a0d96289a01a99b1b1a70e3f64c145b7fac
alice_1  | [2020-02-18 11:46:11.035] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated sk_ai: b59b4270e4c9f86f11fdf6de7b55ac0a783bea06bdc6b587f42476c3983ccce8b494ea3961673b41c7f46327dffc779c8f4bea1b96c9da8651ca05d3cff9902b
alice_1  | [2020-02-18 11:46:11.036] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated sk_ar: 400abe608ecf5f7c4a571ca1a0ddcf89794a03154453a137e8e1bcdf1af14f3129019bf46cf2dda1839072c5e0757115e65a7d2553f26ec1967bd0102a3e1f4b
alice_1  | [2020-02-18 11:46:11.036] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated sk_ei: 3198b83620e4d49521f482e097359fe3725abaed096b6b085d048d8dfc3bad07
alice_1  | [2020-02-18 11:46:11.036] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated sk_er: 720277d420e0cab18d7a24de7bf5d216c321da011cee3281189b2c7581ae26f8
alice_1  | [2020-02-18 11:46:11.036] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated sk_pi: ebf830f774ace785c6de98b5b67f38610790c48e597ef7a5d393892f62b1fd8b09699a8ec05d37f1882cbe949ffc7562f0ff79b734ea006617d077ee7ef9dd6a
alice_1  | [2020-02-18 11:46:11.036] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated sk_pr: d1f5291123455cd912578803de8559e994d20861bf37dd047e3657fe16e63040aef4d769ad19738447c6d64f40c751e9df6867a0e66e594f26dffc90fdd59c2f
alice_1  | [2020-02-18 11:46:11.039] [INFO   ] IKE_SA: 4032e4155ba9ceb6. Sent IKE_AUTH request (448 bytes) to 172.50.1.3 [TSi, TSr, SA, KE, IDi, AUTH]
alice_1  | [2020-02-18 11:46:11.040] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. {
alice_1  |   "spi_i": "4032e4155ba9ceb6",
alice_1  |   "spi_r": "0e37fed63a0db92c",
alice_1  |   "major": 2,
alice_1  |   "minor": 0,
alice_1  |   "exchange_type": "IKE_AUTH",
alice_1  |   "is_request": true,
alice_1  |   "is_response": false,
alice_1  |   "can_use_higher_version": false,
alice_1  |   "is_initiator": true,
alice_1  |   "is_responder": false,
alice_1  |   "message_id": 1,
alice_1  |   "payloads": [],
alice_1  |   "encrypted_payloads": [
alice_1  |     {
alice_1  |       "type": "TSi",
alice_1  |       "critical": false,
alice_1  |       "traffic_selectors": [
alice_1  |         {
alice_1  |           "ts_type": "TS_IPV4_ADDR_RANGE",
alice_1  |           "ip_proto": "TCP",
alice_1  |           "port-range": "0 - 65535",
alice_1  |           "addr-range": "0 - 65535"
alice_1  |         },
alice_1  |         {
alice_1  |           "ts_type": "TS_IPV4_ADDR_RANGE",
alice_1  |           "ip_proto": "TCP",
alice_1  |           "port-range": "0 - 65535",
alice_1  |           "addr-range": "0 - 65535"
alice_1  |         }
alice_1  |       ]
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "TSr",
alice_1  |       "critical": false,
alice_1  |       "traffic_selectors": [
alice_1  |         {
alice_1  |           "ts_type": "TS_IPV4_ADDR_RANGE",
alice_1  |           "ip_proto": "TCP",
alice_1  |           "port-range": "23 - 23",
alice_1  |           "addr-range": "23 - 23"
alice_1  |         },
alice_1  |         {
alice_1  |           "ts_type": "TS_IPV4_ADDR_RANGE",
alice_1  |           "ip_proto": "TCP",
alice_1  |           "port-range": "23 - 23",
alice_1  |           "addr-range": "23 - 23"
alice_1  |         }
alice_1  |       ]
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "SA",
alice_1  |       "critical": false,
alice_1  |       "proposals": [
alice_1  |         {
alice_1  |           "num": 1,
alice_1  |           "protocol_id": "ESP",
alice_1  |           "spi": "0edffee0",
alice_1  |           "transforms": [
alice_1  |             {
alice_1  |               "type": "ENCR",
alice_1  |               "id": "ENCR_AES_CBC",
alice_1  |               "keylen": 256
alice_1  |             },
alice_1  |             {
alice_1  |               "type": "INTEG",
alice_1  |               "id": "AUTH_HMAC_SHA2_512_256"
alice_1  |             },
alice_1  |             {
alice_1  |               "type": "DH",
alice_1  |               "id": "DH_21"
alice_1  |             },
alice_1  |             {
alice_1  |               "type": "ESN",
alice_1  |               "id": "NO_ESN"
alice_1  |             }
alice_1  |           ]
alice_1  |         }
alice_1  |       ]
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "KE",
alice_1  |       "critical": false,
alice_1  |       "dh_group": 21,
alice_1  |       "ke_data": "014d4cafe9e6602b339db94c8be0ea046f4757653b65880f5e9162c23deae8fe45b6898ae07910acfc7014b59d2cf65b2bb49cc31d51b6a98fae6dd180713538ffe300f2fcf8a887a3509ed2ab2ca219a1895879a8bcb13bbd76680143487c51259ec56014283a2e0cd0ceaf81d04a45c2e708d41d08ca205a1a20d5cec26c5cca5952ad"
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "IDi",
alice_1  |       "critical": false,
alice_1  |       "id_type": "ID_FQDN",
alice_1  |       "id_data": "alice.openikev2"
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "AUTH",
alice_1  |       "critical": false,
alice_1  |       "method": "PSK",
alice_1  |       "auth_data": "f16e2780e6f0a275586fbeee646c0ade169de1894c5f460c02668230239e9803a7709f3d2f369e092e64fe43fe026cc63b70b6ec5386c0d0c5e617d626f7126d"
alice_1  |     }
alice_1  |   ]
alice_1  | }
alice_1  | [2020-02-18 11:46:11.048] [INFO   ] IKE_SA: 4032e4155ba9ceb6. Received IKE_AUTH response (384 bytes) from 172.50.1.3 [NONCE, SA, TSi, TSr, IDr, AUTH]
alice_1  | [2020-02-18 11:46:11.049] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. {
alice_1  |   "spi_i": "4032e4155ba9ceb6",
alice_1  |   "spi_r": "0e37fed63a0db92c",
alice_1  |   "major": 2,
alice_1  |   "minor": 0,
alice_1  |   "exchange_type": "IKE_AUTH",
alice_1  |   "is_request": false,
alice_1  |   "is_response": true,
alice_1  |   "can_use_higher_version": false,
alice_1  |   "is_initiator": false,
alice_1  |   "is_responder": true,
alice_1  |   "message_id": 1,
alice_1  |   "payloads": [],
alice_1  |   "encrypted_payloads": [
alice_1  |     {
alice_1  |       "type": "NONCE",
alice_1  |       "critical": false,
alice_1  |       "nonce": "73958401f6c73a1deab21d180778b769c83b3dd124bbc52d8d61cab97bb181b402b87bf8b1db8229ed5fa60cb3095f2a9eb8dcb825cd9118459eeb6324995f1193fc9160d52ca0700b6377ca5191a03c6f1a2bc7308b0c4687ab25f077deeb5b10fe652b6016"
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "SA",
alice_1  |       "critical": false,
alice_1  |       "proposals": [
alice_1  |         {
alice_1  |           "num": 1,
alice_1  |           "protocol_id": "ESP",
alice_1  |           "spi": "92ea861a",
alice_1  |           "transforms": [
alice_1  |             {
alice_1  |               "type": "ENCR",
alice_1  |               "id": "ENCR_AES_CBC",
alice_1  |               "keylen": 256
alice_1  |             },
alice_1  |             {
alice_1  |               "type": "INTEG",
alice_1  |               "id": "AUTH_HMAC_SHA2_512_256"
alice_1  |             },
alice_1  |             {
alice_1  |               "type": "ESN",
alice_1  |               "id": "NO_ESN"
alice_1  |             }
alice_1  |           ]
alice_1  |         }
alice_1  |       ]
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "TSi",
alice_1  |       "critical": false,
alice_1  |       "traffic_selectors": [
alice_1  |         {
alice_1  |           "ts_type": "TS_IPV4_ADDR_RANGE",
alice_1  |           "ip_proto": "TCP",
alice_1  |           "port-range": "0 - 65535",
alice_1  |           "addr-range": "0 - 65535"
alice_1  |         }
alice_1  |       ]
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "TSr",
alice_1  |       "critical": false,
alice_1  |       "traffic_selectors": [
alice_1  |         {
alice_1  |           "ts_type": "TS_IPV4_ADDR_RANGE",
alice_1  |           "ip_proto": "TCP",
alice_1  |           "port-range": "23 - 23",
alice_1  |           "addr-range": "23 - 23"
alice_1  |         }
alice_1  |       ]
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "IDr",
alice_1  |       "critical": false,
alice_1  |       "id_type": "ID_FQDN",
alice_1  |       "id_data": "bob.openikev2"
alice_1  |     },
alice_1  |     {
alice_1  |       "type": "AUTH",
alice_1  |       "critical": false,
alice_1  |       "method": "PSK",
alice_1  |       "auth_data": "953b26b5a9e61e6f98ee21b973118abf6a5fefedbb08466ff0937ac9cbdfc49b9a28bfdfb861ad555dbd512381e91d3554db3cf1754fd4a2ff6b59491598054a"
alice_1  |     }
alice_1  |   ]
alice_1  | }
alice_1  | [2020-02-18 11:46:11.049] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated sk_ai: df3c92b6858875060f915c17000272e0f485378ad6271dbfe79b8d071d9b8d522f19686e0e9db5bf0164a405ad7fcbd580a25bb9fe7f589f989698b08cc359c0
alice_1  | [2020-02-18 11:46:11.049] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated sk_ar: 3c3e7075d3a7190601a020aea0b3ba46376a481e73e23f4c698170d41f4d2779c2cb7bf8e646a1b7b5038ebcb6ce8ca2f3f411f36752e7b14530647aec1b6cd0
alice_1  | [2020-02-18 11:46:11.050] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated sk_ei: 18339f5431707fd825698fdfa8dfc4f203de6d08ceb66e762fb56670dd7f772c
alice_1  | [2020-02-18 11:46:11.050] [DEBUG  ] IKE_SA: 4032e4155ba9ceb6. Generated sk_er: e93a45f53f61686224028c89ec7a6f8870bc2b729fc13b5851ca53d59c5a347f
alice_1  | [2020-02-18 11:46:11.050] [INFO   ] IKE_SA: 4032e4155ba9ceb6. Created CHILD_SA (0edffee0, 92ea861a)
``` 
