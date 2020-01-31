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
```text
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

If you want to see more detailed output, run it with the `-v` parameter. You should see something such as:
```text
[2020-01-31 15:53:30.075] [INFO   ] Listening from [172.50.1.2]:500
[2020-01-31 15:53:30.075] [INFO   ] Listening from [2001::2]:500
[2020-01-31 15:53:30.075] [INFO   ] Listening from [172.100.1.2]:500
[2020-01-31 15:53:30.075] [INFO   ] Listening control events on [127.0.0.1]:9999
[2020-01-31 15:53:30.075] [INFO   ] Listening XFRM events.
[2020-01-31 15:53:30.648] [DEBUG  ] Received acquire for 172.50.1.3
[2020-01-31 15:53:30.650] [INFO   ] Starting the creation of IKE SA with SPI=05ccc375c7c8334f. Count=1
[2020-01-31 15:53:30.650] [INFO   ] IKE_SA: 05ccc375c7c8334f. Received acquire from policy with index=917985
[2020-01-31 15:53:30.771] [INFO   ] IKE_SA: 05ccc375c7c8334f. Sent IKE_SA_INIT request (1436 bytes) to 172.50.1.3 [SA, NONCE, KE, VENDOR]
[2020-01-31 15:53:30.771] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. {
  "spi_i": "05ccc375c7c8334f",
  "spi_r": "0000000000000000",
  "major": 2,
  "minor": 0,
  "exchange_type": "IKE_SA_INIT",
  "is_request": true,
  "is_response": false,
  "can_use_higher_version": false,
  "is_initiator": true,
  "is_responder": false,
  "message_id": 0,
  "payloads": [
    {
      "type": "SA",
      "critical": false,
      "proposals": [
        {
          "num": 1,
          "protocol_id": "IKE",
          "spi": "05ccc375c7c8334f",
          "transforms": [
            {
              "type": "ENCR",
              "id": "ENCR_AES_CBC",
              "keylen": 256
            },
            {
              "type": "ENCR",
              "id": "ENCR_AES_CBC",
              "keylen": 128
            },
            {
              "type": "INTEG",
              "id": "AUTH_HMAC_SHA2_512_256"
            },
            {
              "type": "INTEG",
              "id": "AUTH_HMAC_SHA2_256_128"
            },
            {
              "type": "INTEG",
              "id": "AUTH_HMAC_SHA1_96"
            },
            {
              "type": "PRF",
              "id": "PRF_HMAC_SHA2_512"
            },
            {
              "type": "PRF",
              "id": "PRF_HMAC_SHA2_256"
            },
            {
              "type": "PRF",
              "id": "PRF_HMAC_SHA1"
            },
            {
              "type": "DH",
              "id": "DH_18"
            },
            {
              "type": "DH",
              "id": "DH_17"
            },
            {
              "type": "DH",
              "id": "DH_16"
            },
            {
              "type": "DH",
              "id": "DH_15"
            },
            {
              "type": "DH",
              "id": "DH_14"
            }
          ]
        }
      ]
    },
    {
      "type": "NONCE",
      "critical": false,
      "nonce": "b0587184259e78b2c54ad47044009ccd6dff32a24170f9c49318929d5ea371204cdf223ab0d5d2cb55acce29a517d7b19bbd2837f41874b50591ea5f7d47670b14c61b2ad418a67143451349c1f5076f23a9e746e4c8828ec077eeca1f49de0ec5e30375653438a8d9b81e631034392b80ccab5d99b84a5b06ec50e2c888fc99669aebdfd93504d83342009351f66e953f3faf45008903e455d29d203e327807ddae2c804f8188019d527be0da684b0413122d286b11e85df8bb7ae82631241fe3395a47c4463a97b8b19083426f8e427bbca97baf0373afbbfa0d14a69a47b6de"
    },
    {
      "type": "KE",
      "critical": false,
      "dh_group": 18,
      "ke_data": "b79607c77d0dd9458bd77f09833046c7e0c74ab3e9330fdc20f07d00d3ec1ff6066cbd96d0eb1a13c739efb33a1fbfd4aa06ebb77bae2215367ac93ac91e05e1cbfd30e39d67c2b3687f5af24c9c295b48a58abc1102e951ce36e55cb07ffdbed666aa72e0c61fe1637f0d66d6dd337ea4cc58fc62bfddf73a35e6529715f60a7efb746f19de680a05095551002badc404e5f5981b3592365ff5acb1d51940cf5018b58466ea0cc19dc55ced830bff4ac5e1a3c2e740a2162455b19933572c2709c350eca2f8e66faa0b3bc076a3e1bdf8760772bf34e535079ff64f2ea8cb503e62c387cf4719630b6485b31d1c59bcc087e086ad6a29e0e6d42c60e2b11da272b328427f00f248fff97f86b6d3ccb08c2fbb7df32bfc52de59bfe0fb3ad359ba0301d20b601ba6caaa199b4be8be65afe88e1e01f255bfc2578559c437d4445cfcbaaf6459903f5e03b106fe52685ed688bb99164fdb4c7797957a429abef4c741b80e16acaa64973822dbd7c7fe314b74c33aa7af6dc50d98accc8b4ba0042d865219c38b09316e0f7e318bbd84e0c0956c5fec55e3559657667505b17c81f8874a7fd954ee030655009f133914858f794e62c0d81c2f7894cf01c3836c2a3b785530f6a993f018632bcdbef7ce817d320e58fcb8184b098e1ce01cc3d4f3a3baf60810a030f78b2f3bc04b92434f3bc2f4b8844ba9ea4547c85879c06e5b50c7014d15f30abcde91b73b235fe88b58ed535d3ea36eb58179f017e1e6889e9a2ff31279a829385f3208eb6477a1a43a3f0cb5d986945708b17a3b317b50488f2e00f799672ff3f1af5daafcf2df75c80a6f183e935725fbb902cbfb6c42d1c5793cc62a01b48882436c7675e5e7f6b55dccd4099ffb1120685079bccd2a5ce00559ff4fcfa96f8852fc7c32fe553de7bef299949ea02dc6323a90b540b43d5ce64608c48dbc787108a5b7bb3bd9b2baedb80834f5fc1e33612d5d140d43afb80efab89abb5dd9eabf61fb185fc286fea925d231d5a649e43af40d8fd8288eafdda79d3643bbbdb4f30315d16e9452ff365bcddfecda84c6747b8e2ed1c8b23911b9042d2f2ab4e5779b5a7a86474e939b089cdb45a44123a2c18aa4680459bfded468c0b67e88d0ffd1eb0c22f7508f02fda86db8dfec8815befba41b35e8de2519f4e1e39460b53d23146898d4dc3de7349e58ab041feb48cbd3fde9bcf2ed3878d769241df8fdb7b95718e40a2066e0193cf4ddddbeb80e81b6ae538672170a874b1b1974448d419792ffc7559d2cc31afd6309ca50fba2c9652683e5c4884f9525ab19a2bfc031f38c456fe8cc3a76cf65b378afee51e5dbbe01dc31d65d03be54505accf0635ce49535102ea8c262a42bc43a25990847ada676854a1472cadcbe5bad2861dd2f6e3bf70b151e37c943b9df2bfad480d0abed1bbb85bc"
    },
    {
      "type": "VENDOR",
      "critical": false,
      "vendor_id": "pyikev2-0.1"
    }
  ],
  "encrypted_payloads": []
}
[2020-01-31 15:53:31.002] [INFO   ] IKE_SA: 05ccc375c7c8334f. Received IKE_SA_INIT response (1237 bytes) from 172.50.1.3 [SA, NONCE, KE, VENDOR]
[2020-01-31 15:53:31.002] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. {
  "spi_i": "05ccc375c7c8334f",
  "spi_r": "800aa831de8fa513",
  "major": 2,
  "minor": 0,
  "exchange_type": "IKE_SA_INIT",
  "is_request": false,
  "is_response": true,
  "can_use_higher_version": false,
  "is_initiator": false,
  "is_responder": true,
  "message_id": 0,
  "payloads": [
    {
      "type": "SA",
      "critical": false,
      "proposals": [
        {
          "num": 1,
          "protocol_id": "IKE",
          "spi": "800aa831de8fa513",
          "transforms": [
            {
              "type": "ENCR",
              "id": "ENCR_AES_CBC",
              "keylen": 256
            },
            {
              "type": "INTEG",
              "id": "AUTH_HMAC_SHA2_512_256"
            },
            {
              "type": "PRF",
              "id": "PRF_HMAC_SHA2_512"
            },
            {
              "type": "DH",
              "id": "DH_18"
            }
          ]
        }
      ]
    },
    {
      "type": "NONCE",
      "critical": false,
      "nonce": "ba755e3e919545d5e4e5f911456f416446a63c6cde56944fdbcb930e6d5d0f542c30771243c33d6bb055e147496b5dc3b7e29ad7cc06bbae3a94a3b6de4a679c600ff0e63d19ca11f423440b46fc4bf9dd3ee94db4186d91007dd38e0bd25c70c2900cadc2e4"
    },
    {
      "type": "KE",
      "critical": false,
      "dh_group": 18,
      "ke_data": "05649eb09ff0e1eae93d17e88e0ce901150c5e8599a221e4a9b8a9b3de39e4d9bf182d34a01ac928e54141706e64f36c4ac6b71dca17c79edbad2a420525e51dec63eaed7f5f15138f6ac2a96bfdc1d72bb900d2e1941ab5d9152633df10fb01e78647d33d5b96c3b381e78353d61810c817c2d9dd3324c9a553a84ca7ebdc2bfd84adbb3d26c00b83239f70ff4a031504b3c417c31533a5d4f148bddbe3fb42d9c9012ca618680001b5add4c89cb35361d6cde94db1a4beb3873d561c9ed1c0a6c4006287d120ecca4b61c26553ad43ca4d66726beb88d9eb3d99ea3ae87241a31beb1136857776b606ea769522be04754c4465bea305fade69f97593d0ed09b3741b37e79972af5a007675f7e4f3d6d2ed8129e7c805ec24fad6fadfcf714e700aa12d1b94a9854907d2eac7c496e44ef59fd54ac14180d66f77151f1dab9fc9ccc845d30a5452272c8234e2de2a4e153df242c8252243eedd513889f8bc3c0b66610cd5725efe9e3200af405133ec353175c57a5bf51ada0985f1cb9d5020786a87bd31779d929063c5cfc749b01ceb2673d227b2ffc02ec9c80b614a81f0e4a8d087e01e81b720ddbf90cad1b46d5edacd52d87ad30bd32036aa1c18e5f1ccaad1cc3a4aace52e32aefe3f6687c24e5268d14c6861efe0528a78fd9891e2c97fe44308c37f14c509497cec4f19b8b5e3738d5ef77b3581134683373623359ca839512b857dd0ab295581df49e6dc21cfeb807c35e6f9f6b8a61f921b77abd64f15458f4f210f9c04b1fcca588d985e21e039bc7ac5c51e15bb1e76843d49f6ee719c4cb5f34b35443bcd9e6de6d0120e796c44ab2be0baf1e2f372a060d2d9579a36b49f3004afbb0af6ab2593d2baa517006c08cd6c4e52fa6f18352f1b77b21ed2f99e249bd970c550919466bfcdb0b1eddc2eb5d6d59ef508910074061a076d3bc4871d7f3cd78b53838c246a6f0c7a067d9db1dddda91d6ec84d3f2795edbe4ceb24fe0aa5043dbb65e0ad6d8890283c687be070399548ff1e4cc78c76ba48d9d0719512033017dd92ca7773308575d6f1a80f02215c17edb7cd60d57308ee3cf7cdd58d8b4c363fdc0bb5ddf83a84042b046208dbc0b625d250406d0f31b26375875c6ddeecf92b2252c812bacb803282c73a9ec0ef389b871d45d296febe2409389cfc6fbe4cb3444c26a74d72cf3b20eab86c86192a0c90fb6eaefb00a5190fa8824dc273671d54324810d6415c0f14d92e5e560723c472ab45caa770d2f14ac4a7bd8b1fb6b40623bbd7c6f8b1dea5f0d8b29af9ba5d1c36872d061b5f86d19fb28b26d85038925ca51c3879c03b163370455cbe50a5bbf4a899099a5266af220afb87480ed454c01dbfe250d25e90095d130cc532a66cf3b9e02fdeeb16be367a38ac9d230289ca7141d6ac06e3e46a923943b2d7175d64659a"
    },
    {
      "type": "VENDOR",
      "critical": false,
      "vendor_id": "pyikev2-0.1"
    }
  ],
  "encrypted_payloads": []
}
[2020-01-31 15:53:31.117] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated DH shared secret: 9190eb0a6edaeece5127a52dfcf23b3385a4af392073317da885c0361180f8f93529b9761eb691b8a5f2e548a1e887a5765800c878e87b401f101f740691202feee4808ff0f0050e0551941a745b09cb74c3dfc716f4b96b1b9e906607bd0332d14bb9c984675e243b6999822fa26d87042b76523eb4424faa19bfb11c9d4ff543d3e86937e6f9cb1bfde6eaeb9e79cc2c7b7a976e582261202dc6061e6c4a412f1a1ddf5971598a370c16426d71eb58488682c8f71aef68fe6ae47e9d3309c9aad4a397282a3773ca29f6e52bdcf6ffbd83832ba5818d224f523c2b40b5aa5096e7f6886ebe93dde51ad6ef936fbda6432e654ff316a5d79c10d98a7b6bdf4c2dd60e2381ed492c84447131860c4a6af7950bd1f1521e60b9cdf0a186eb88ef1833307b8ff0cf1f588e189931bf435ef48e5a7c3d4b023f7ac645bd5bd85e2ae56838947ae3629077d38ded3133fc7b24221f48dadbf7754cf58cb2b1b51770d3986e088ffdb47c0e03caf015b4fcd5e331c39e13b7c8b11ee305a7c4d5c3eab1a03f4370a322ef8ad3dbd7367ed9065229cfa8b661fbf7873bfb3df1d0e30e08742b4d98cd26e9f17804104e077b2544573cfe006ac48442910ae949c1da927072c507d62744233ccd23d91eb92730ec220cd62ec0155f64324ede8bd0c1558ade1dc476d3a53a83ab24c57934151bd0f2d2392060ed394126ea1d705b1bb43147a5cbcf65790d2e3e1869bf7073c52d7265014d20ab65fb88b1571dfe9f5fe69a49574b522514ea29dc65465fd767875a12becb90f45d42bc488c22902757cf8e324fc771a8556d573f48bf604c4b4cd115f47cbd8c29499bc9cd792dc591398f1e0ee67a83a559e2f2e2d43ab903e82ddcf40a339c11476b8aab3295cc8ca3774ee06c8fa7157c9630b7b1cb7c1c02fbb377e76729381fa1caee863ffd0d22ace77b646e0e29e729e972cbf8192d4ccf8f2a23835b748d367ccf824a11be788717f885dacf98b7c6d014a5e6555687cadd68bfd79656f41ae470a2b04021196df642893d789b736e708a4e74890bfda69c052f77257e370d715a692289b470d37546ea1dd95a87f472502ec307c4bfc82900f756572e97ccedc6f3db32b45f28bc48eea6afc38fec181c7c4c1f129f1c97684ac6c90b24327ea352c8ad4638707fa7591bc60672cd4735bd476db5956d16290203af19e63b01ba7d8ec345c75a8c0270b0113b374f3c760b6633a8e87a91acddeddd33be01f0eeb0c235ede513e6a1e6bd58ce8f29bd2f4f7a619ed8975e42b8d9180c7aa7a910c9f358a2bc7f6a2fa37a3109b57932bb88a2df5d9fbe12e3d327461eedaf75e66293f505940bad473ce782a3652a107018899f0147c2ec87021be51b977dc1d90d4bfd391a9fbc45c2719c38cb046c77d6be658ea6817c6acdf27aa86ecb8255b8078306
[2020-01-31 15:53:31.117] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated SKEYSEED: 0b44fda6c2c16465c9f6e592efca0b7b88cd242f93ff16df5e9ad5bb74d2bec73ab88a730a05d0675d17bb0cd36d04410af17f4fdc5e99114321ca6f2d5d20dc
[2020-01-31 15:53:31.117] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated sk_d: 470529786f84dcb53c9237f2b58e69b855b00f6e679c524ad3dcbd7bc632b11de7ac4cb4ca6fc4dc33fe58ca80cdd7e2f6a219f9b56e8117ceee8cf8433c2dd8
[2020-01-31 15:53:31.117] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated sk_ai: 80511f6aabec8a0116ef20867fb3b2d6e02859d19e80ad7a99032dfe4894f4a97d3194929b9b0499be94a5be56a92c1a2a43d768d266880e395a2edc11f2aa22
[2020-01-31 15:53:31.117] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated sk_ar: 8b75c60c2f6d0da52d69885a83da109374f924533936eab8ddbc3843bd7d48e3c42761551bb128aa01552de8937356294fbe2558f389a60e676e000275b95fc7
[2020-01-31 15:53:31.117] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated sk_ei: 9dfc0f150180b2aaf3bf357de553ca7c8a85f54079279723204db653635cd882
[2020-01-31 15:53:31.117] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated sk_er: 2baa9a611919b448244c2895148ee5cb83e97b3df8b798daf359027e9164492c
[2020-01-31 15:53:31.117] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated sk_pi: 7e7cd08c39cbbf4484df66ca15fe7b829b41c5685bfe8fb1f902fc5f489b151f17422c189df829f80e3be2c21658fee4f58c18eff69c953deb2cdf336e6ff80b
[2020-01-31 15:53:31.117] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated sk_pr: d58d287805beddc74832b31d55ef0adf8ea5a941fffa511eeb4cfa4b359f7733e71ea2b845b92cc08b51c210a41635834d1750b8c55f01afbc79037d44ccb6dc
[2020-01-31 15:53:31.227] [DEBUG  ] SIGNING: 05ccc375c7c8334f000000000000000021202208000000000000059c28000084000000800101080d05ccc375c7c8334f0300000c0100000c800e01000300000c0100000c800e0080030000080300000e030000080300000c0300000803000002030000080200000703000008020000050300000802000002030000080400001203000008040000110300000804000010030000080400000f000000080400000e220000e5b0587184259e78b2c54ad47044009ccd6dff32a24170f9c49318929d5ea371204cdf223ab0d5d2cb55acce29a517d7b19bbd2837f41874b50591ea5f7d47670b14c61b2ad418a67143451349c1f5076f23a9e746e4c8828ec077eeca1f49de0ec5e30375653438a8d9b81e631034392b80ccab5d99b84a5b06ec50e2c888fc99669aebdfd93504d83342009351f66e953f3faf45008903e455d29d203e327807ddae2c804f8188019d527be0da684b0413122d286b11e85df8bb7ae82631241fe3395a47c4463a97b8b19083426f8e427bbca97baf0373afbbfa0d14a69a47b6de2b00040800120000b79607c77d0dd9458bd77f09833046c7e0c74ab3e9330fdc20f07d00d3ec1ff6066cbd96d0eb1a13c739efb33a1fbfd4aa06ebb77bae2215367ac93ac91e05e1cbfd30e39d67c2b3687f5af24c9c295b48a58abc1102e951ce36e55cb07ffdbed666aa72e0c61fe1637f0d66d6dd337ea4cc58fc62bfddf73a35e6529715f60a7efb746f19de680a05095551002badc404e5f5981b3592365ff5acb1d51940cf5018b58466ea0cc19dc55ced830bff4ac5e1a3c2e740a2162455b19933572c2709c350eca2f8e66faa0b3bc076a3e1bdf8760772bf34e535079ff64f2ea8cb503e62c387cf4719630b6485b31d1c59bcc087e086ad6a29e0e6d42c60e2b11da272b328427f00f248fff97f86b6d3ccb08c2fbb7df32bfc52de59bfe0fb3ad359ba0301d20b601ba6caaa199b4be8be65afe88e1e01f255bfc2578559c437d4445cfcbaaf6459903f5e03b106fe52685ed688bb99164fdb4c7797957a429abef4c741b80e16acaa64973822dbd7c7fe314b74c33aa7af6dc50d98accc8b4ba0042d865219c38b09316e0f7e318bbd84e0c0956c5fec55e3559657667505b17c81f8874a7fd954ee030655009f133914858f794e62c0d81c2f7894cf01c3836c2a3b785530f6a993f018632bcdbef7ce817d320e58fcb8184b098e1ce01cc3d4f3a3baf60810a030f78b2f3bc04b92434f3bc2f4b8844ba9ea4547c85879c06e5b50c7014d15f30abcde91b73b235fe88b58ed535d3ea36eb58179f017e1e6889e9a2ff31279a829385f3208eb6477a1a43a3f0cb5d986945708b17a3b317b50488f2e00f799672ff3f1af5daafcf2df75c80a6f183e935725fbb902cbfb6c42d1c5793cc62a01b48882436c7675e5e7f6b55dccd4099ffb1120685079bccd2a5ce00559ff4fcfa96f8852fc7c32fe553de7bef299949ea02dc6323a90b540b43d5ce64608c48dbc787108a5b7bb3bd9b2baedb80834f5fc1e33612d5d140d43afb80efab89abb5dd9eabf61fb185fc286fea925d231d5a649e43af40d8fd8288eafdda79d3643bbbdb4f30315d16e9452ff365bcddfecda84c6747b8e2ed1c8b23911b9042d2f2ab4e5779b5a7a86474e939b089cdb45a44123a2c18aa4680459bfded468c0b67e88d0ffd1eb0c22f7508f02fda86db8dfec8815befba41b35e8de2519f4e1e39460b53d23146898d4dc3de7349e58ab041feb48cbd3fde9bcf2ed3878d769241df8fdb7b95718e40a2066e0193cf4ddddbeb80e81b6ae538672170a874b1b1974448d419792ffc7559d2cc31afd6309ca50fba2c9652683e5c4884f9525ab19a2bfc031f38c456fe8cc3a76cf65b378afee51e5dbbe01dc31d65d03be54505accf0635ce49535102ea8c262a42bc43a25990847ada676854a1472cadcbe5bad2861dd2f6e3bf70b151e37c943b9df2bfad480d0abed1bbb85bc0000000f7079696b6576322d302e31ba755e3e919545d5e4e5f911456f416446a63c6cde56944fdbcb930e6d5d0f542c30771243c33d6bb055e147496b5dc3b7e29ad7cc06bbae3a94a3b6de4a679c600ff0e63d19ca11f423440b46fc4bf9dd3ee94db4186d91007dd38e0bd25c70c2900cadc2e4feb852b5009df356ef1cb3bdc1bfda158681549d3ad2bbeb70083b43a4954c97b9441afe8766147a1380b6563990ca67b3edd7a1252d19f57010aea0d929fd7e
[2020-01-31 15:53:31.227] [INFO   ] IKE_SA: 05ccc375c7c8334f. Sent IKE_AUTH request (1440 bytes) to 172.50.1.3 [TSi, TSr, SA, KE, N(USE_TRANSPORT_MODE), IDi, AUTH]
[2020-01-31 15:53:31.228] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. {
  "spi_i": "05ccc375c7c8334f",
  "spi_r": "800aa831de8fa513",
  "major": 2,
  "minor": 0,
  "exchange_type": "IKE_AUTH",
  "is_request": true,
  "is_response": false,
  "can_use_higher_version": false,
  "is_initiator": true,
  "is_responder": false,
  "message_id": 1,
  "payloads": [],
  "encrypted_payloads": [
    {
      "type": "TSi",
      "critical": false,
      "traffic_selectors": [
        {
          "ts_type": "TS_IPV4_ADDR_RANGE",
          "ip_proto": "TCP",
          "port-range": "46546 - 46546",
          "addr-range": "172.50.1.2 - 172.50.1.2"
        },
        {
          "ts_type": "TS_IPV4_ADDR_RANGE",
          "ip_proto": "TCP",
          "port-range": "0 - 65535",
          "addr-range": "172.50.1.2 - 172.50.1.2"
        }
      ]
    },
    {
      "type": "TSr",
      "critical": false,
      "traffic_selectors": [
        {
          "ts_type": "TS_IPV4_ADDR_RANGE",
          "ip_proto": "TCP",
          "port-range": "23 - 23",
          "addr-range": "172.50.1.3 - 172.50.1.3"
        },
        {
          "ts_type": "TS_IPV4_ADDR_RANGE",
          "ip_proto": "TCP",
          "port-range": "23 - 23",
          "addr-range": "172.50.1.3 - 172.50.1.3"
        }
      ]
    },
    {
      "type": "SA",
      "critical": false,
      "proposals": [
        {
          "num": 1,
          "protocol_id": "ESP",
          "spi": "ad8b91bc",
          "transforms": [
            {
              "type": "ENCR",
              "id": "ENCR_AES_CBC",
              "keylen": 256
            },
            {
              "type": "ENCR",
              "id": "ENCR_AES_CBC",
              "keylen": 128
            },
            {
              "type": "INTEG",
              "id": "AUTH_HMAC_SHA2_512_256"
            },
            {
              "type": "INTEG",
              "id": "AUTH_HMAC_SHA2_256_128"
            },
            {
              "type": "INTEG",
              "id": "AUTH_HMAC_SHA1_96"
            },
            {
              "type": "DH",
              "id": "DH_18"
            },
            {
              "type": "ESN",
              "id": "NO_ESN"
            }
          ]
        }
      ]
    },
    {
      "type": "KE",
      "critical": false,
      "dh_group": 18,
      "ke_data": "90c5e051604b6fa2511eceb812e5a0004e8c597e05c079c40eca9fe7954f74d93113328a3d94681eaabbdfca49cd35988a7880b6e17f9cb4581aa5e16085c11692088afe42c44cf41562a3e3b0d167c3a4fce4db7154061ea7ed065d355e7de2b0b45825d7ca8baa9d58074430c16446db3e9935c559c1161ceed520846ea709f653a33d43122850a79f446b0c46ef934a5dedef75c07d77ee10f09a97dc91b2aa7d4361680326d6a0c368abb99c25eec1826c772713cb980536109e3cd26b1810d435bddf1dbbc7eafa0955c082bdf8f461fe25e32559f85f80139d16a691bca58add49b3ddbd741e27a3d2acbe2e0c6418076735f55fcac15ddcc045e5ee4db48aa81edfebd682dc17f0778291f3a6c97b66dbfb955b212b0558f1d0cd8e2544dd869343184a8eeb4da8ab93ab52b6b51c6192aebd237e4fc09c3a8c5ceb460d090d54d5f8e7e603ba7af602e0d5bb3c31b566343c10b1bd174cf19a3b00b3f0e0937a7ad4f801dbbacc3dbbb90361d77bb5c6bce4bb3edb9c41bb6464e5905ba11706e20c467151f5ed913830c01889f7d60851a3bbb8f9a693b7783f90eafa9229b049a5cf25fb570eceae1059025589a05aeedce19b0a444179bd51324db4b31007b2c33ea9ba310fd56f82559c84a14a36983d70fd2cc2b48d904dae282aa67a59f57e30e6bb6d2d731632815e1d874d04a8259781c552b8106072c8cf4b329dcdba6b5a57c8658207ea3b2546d0821d57a58310c689fa4ca3fc9067091392adffe2a2a6743d378581ef47e30cd5223611e56ca24c08bb4aac5bae6749cc124dfd8ee24e9c3088a8fff9d3338650ca693f4a2c368c07f2b9b64fe7dfc8e7d07411e64f653f3239a1c213b4478bd1ce2070baaa32824394fd2e5c8ad390522d6333259870640dff7486dde77cbd44fc1f95f3035b0f7ffbb02937cd947e6eaab2a2813df0c4ce8f875e2fa76df552a7fcd80eaf75e27916185ff1c489f3be72ff7ab05b840719b9d080324ca81897b6bfdb1be53ef174fe5016533cbd2caebc62d5ddf3a1980b46c6ac72caa919bd9c68f98656b762265156d98b341034b894ebaf6fff5417f31d8e8300860c26beaf5692a73876352288661516b822124f20795160ae0f4472436f12261aea0f8734e9a335d75094adb52a64d68fc582a7d06cd85b094e947f595c8258caafc8174d088a31561a4c1af07d760de08f2a3e569dcd9373c6dd04639296168c20d87f995f8a451d84859ea440cf2d4d20023e5fefc9b143ee94ee2d88c93776a08078715c42f45391e0f10fb587ee4f0bac38ce57957fa2472a21813c7f2cedb90e7c8ab438a8d9ee06050b80630969d0b47e07472a94ff16e5be4a9ce0f27a1d12015a3793e844584986159553d60e4a890f430a8695fec15a42e825edc9a1d252c1f31f3650c57e4e2deddecd602b169b"
    },
    {
      "type": "NOTIFY",
      "critical": false,
      "protocol_id": "NONE",
      "spi": "",
      "notification_type": "USE_TRANSPORT_MODE",
      "notification_data": ""
    },
    {
      "type": "IDi",
      "critical": false,
      "id_type": "ID_FQDN",
      "id_data": "alice.openikev2"
    },
    {
      "type": "AUTH",
      "critical": false,
      "method": "RSA",
      "auth_data": "4f5c9cf5dec18a04448e52da949a0598f94b61a81b39dc74a57db7454a33758b775a394e3624216052513dcfa76d90674bb1efacca7a0559c04f0968d7c745add9eef6e9d64792071fd7bccdcbeffef49e35953b5f23d6d13c17b9723fefc9738c6148c1d2f92cd25f11d191da02a71b3d75c8ec22554c0c74a2341911b817ee"
    }
  ]
}
[2020-01-31 15:53:31.451] [INFO   ] IKE_SA: 05ccc375c7c8334f. Received IKE_AUTH response (1424 bytes) from 172.50.1.3 [NONCE, N(USE_TRANSPORT_MODE), KE, SA, TSi, TSr, IDr, AUTH]
[2020-01-31 15:53:31.452] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. {
  "spi_i": "05ccc375c7c8334f",
  "spi_r": "800aa831de8fa513",
  "major": 2,
  "minor": 0,
  "exchange_type": "IKE_AUTH",
  "is_request": false,
  "is_response": true,
  "can_use_higher_version": false,
  "is_initiator": false,
  "is_responder": true,
  "message_id": 1,
  "payloads": [],
  "encrypted_payloads": [
    {
      "type": "NONCE",
      "critical": false,
      "nonce": "ba755e3e919545d5e4e5f911456f416446a63c6cde56944fdbcb930e6d5d0f542c30771243c33d6bb055e147496b5dc3b7e29ad7cc06bbae3a94a3b6de4a679c600ff0e63d19ca11f423440b46fc4bf9dd3ee94db4186d91007dd38e0bd25c70c2900cadc2e4"
    },
    {
      "type": "NOTIFY",
      "critical": false,
      "protocol_id": "NONE",
      "spi": "",
      "notification_type": "USE_TRANSPORT_MODE",
      "notification_data": ""
    },
    {
      "type": "KE",
      "critical": false,
      "dh_group": 18,
      "ke_data": "a66ef0d0801bd65a800cc4bcb595372b04080cf8ebe98880da08e255b0499a50ab8758b2c58d5c1d383cce3817ba7ba1a2701c10ab173a3e53ffdd507fb1f879b930ebe2b9c8839615ced66f1d7692fbf376455e53449082fcd08ff7fe2aa69e2133f552d0c2bca703d119bf6fbb6e31414c56d7006708c68b73666e3f03a981731b6ac31d68ec0d6a87d62fb964f9ca6f11a536e70b8a99e748f6db859168a76c04fcc01abb13c60b3131c0f6ffe4fc62b11f8614406569f9cb79e1ecde27cb20d44bf79b700b4eb8a37ba024e78dfc478b5d133b19cf97484cddc3d0df4443ca80f462a626198ccbfbb1b30766cebbde264609faff9b9f7834e4ef8db0a5d398ad1db45d70abf4c8f040c1dff66aae2d7e2e1ce143624da48968e9a2f93907c4364f19176eff347a10c0b5f1485f0396ee6fb91d32ceb0c7ac7173fbb478e54ebe002fa39c1903d11aa082cec7b08f2b2446a5bba288a3905492aad0778d0af51b97ff5aa2437bab0dc8d7bf6e23878a493e9b389a32f489318570b12a3af330d5d3ac97c2141a1b33918de407fa1b895f46f60b702d0e74f677b1ee1fc559aa89e6708baec0b3dad7ec5b970e897545c5c9836313cd62e2493e7ad36ebbb54baf87419219cd246a7d5baeff08e6726d94b96e8c4e64705a5120cf399c6b2b308b1c2512681eb18c3df7c4f315f7b7aad15ef6aca2545ab9ef691afbf660d2df6627c968de84ed7ef500f9150fa28f7266891397a83f183c3c9e4155a0f251292c362bab76f8d4a4027ed129c5727865240ad2eaa1c1b4e0a1ee233eac58acb17fc4a3f8e602cb72a5f34580e597d05c5dc8a580fbd43c08a8224a6aaf8a4a2e3b861c1ffa58a979a530732cfce94d3ac9ab0d227e00ddf50a284636e2bfd331753743da5a83224f6b5a859f28de4081208a6fb2849951b9ff7b2771ce2031dc94231dc619979caf8699f610b6836dc4990d024e7ac24879ef563b184ac51a082bdc29031f58c2327728c0b305f3ba5bdd7c8ea34c6a9c7227d13af4a5c019334ee6fa18da8ebdec15a9c821cdf5e14ae108c3ffca12e70024dece97ffd28c125811ee6a908330858fbc0ec6e3dd6f1565107cf63b6c7a851114b5bfd6c137ba79f0ba8200f8bfa6ffbdba8a57cc786f9ec7d40a6d6f72dfb96e5a675d057e2b5f5ba5b1ab56b19b5ecc0aaeadc671cae6dac7433555167bc330e1050bb3bc5ade8940586581213cb846f75fbbf364737857a4c21fa90206224f86425a9afb2f7312363ad4d146d66e4246847ef0ecf165104a6efd20152bf6f571e499bb6d91bff0a07f1759b5edb08e0f9a5fecdda0e720073682d3d8f9415f6d796623fc4e05c2fabb16fb221efb32280535673908a0f21b7e3c7e518bfba267cb967d8ececb5a27596f2d9de7ba3df113e38374644cbc6c2639295fcb9ba6d8d24e0c72"
    },
    {
      "type": "SA",
      "critical": false,
      "proposals": [
        {
          "num": 1,
          "protocol_id": "ESP",
          "spi": "979b590d",
          "transforms": [
            {
              "type": "ENCR",
              "id": "ENCR_AES_CBC",
              "keylen": 256
            },
            {
              "type": "INTEG",
              "id": "AUTH_HMAC_SHA2_512_256"
            },
            {
              "type": "DH",
              "id": "DH_18"
            },
            {
              "type": "ESN",
              "id": "NO_ESN"
            }
          ]
        }
      ]
    },
    {
      "type": "TSi",
      "critical": false,
      "traffic_selectors": [
        {
          "ts_type": "TS_IPV4_ADDR_RANGE",
          "ip_proto": "TCP",
          "port-range": "0 - 65535",
          "addr-range": "172.50.1.2 - 172.50.1.2"
        }
      ]
    },
    {
      "type": "TSr",
      "critical": false,
      "traffic_selectors": [
        {
          "ts_type": "TS_IPV4_ADDR_RANGE",
          "ip_proto": "TCP",
          "port-range": "23 - 23",
          "addr-range": "172.50.1.3 - 172.50.1.3"
        }
      ]
    },
    {
      "type": "IDr",
      "critical": false,
      "id_type": "ID_FQDN",
      "id_data": "bob.openikev2"
    },
    {
      "type": "AUTH",
      "critical": false,
      "method": "PSK",
      "auth_data": "2ca59f136fd3d09a9f9470eaec56500a92e9fb39fea576733ab87a104dfd96fcb91c101b7d0428820ee5fcd5b184c6ba1924180441e9692b44155344a43449b1"
    }
  ]
}
[2020-01-31 15:53:31.566] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated CHILD_SA DH shared secret: ef5aabeab9baafb5c43f5d656a91d4c51cda693caf92925b4cc254d65706c99cb00da601ccee1baba25f3dbb467401243e095282ee0652cf93759e3f76f9fe1d089e9ee5e9ed6ef0da0c50853453d83b30c472c3f416d86fdba671062929f20e39b5c188fddacac7a3e871367d13addc391c56d83b32b0d03ea514f3e23154dd519aabd5e09a1d06f44b350beec50af6842cc299e67bbd7ec740670cd8ad720c3f68998e0eec92c8e1c53ce7a4a637e9650101258ee873551c7abc15cf4cf1d71ad23d3a710b08c8b0768cabb3ffb40c359828e15ba9863377bc154cfe8dec6d9a12d5e0e9ae7bca161021516ae0f12dc5a4844d27cd3bbc7e774156388f0807851a692a468e9f1bfedef045472098e6ebec9564f447c1f687341ef8d1693d6ee016a1a58cd912a6688becb93b356fdb1a9a968ddd355d8b6798a77ddc2f6ebac5e0f4f37617094213ab034f077b47243b6de8d54b5f13d9c839a614591e6eb1d80119ed578bd1b62898ed3b5c56124ed029d0a1335d9d11ca8f75baca6215e901e6c40269594058356d56bf1466d9b57f5cda885adc3324d99c8e395c73759d52ce376729e03f4a5456e3e3c925e38a2be819d6351b6ac9c159599cf118bfc19f79ee45ed1cb2eb9750a7448a2626a219fb31c09ef52342f1e5d738eea90f611a54220f3eb988114842c400d100ac220998b658a417a5dfd405f7e0dfd8eb9e475957cd9cfc3acfba57b68d2ff817089900ec017772f9f7636c3415472fe1cf4048633af89d22efca94bb6d4dc370b94a8a129005e7d574f9739808e00d78078e2592ee3604b7c47fcb9e8ced6c6e052e3efe03478c5826b876fb551e6b8c2bd35d69cc4f5a0cf419f50b5beca32b10a2e1a57d6551cee26ff710928f7b3a9d6478b828039909b1f608227f4b5779427c779207f6e51a57e1489ad6c5d3c67fb99482a4d713f5903e689f265d0788b831ebdbf60b49468ce1fd338131e7ff7034b8f77da1596b217c5cc9cf587f08ff94a42000a1ca6377fbe691828f12a708ed56f26032f2833fcabf0e6630bc3a07d8f8a3547de6dc44bda51ff12856b86f21bf1f84ee555d999217eb6eba018d914033253479d21a6cb28e1eb561efcac8a97f2371c06c5076944f980155a9a0a44907957af8451b26b9b975bab9e34e6604492a70cab9fe0ab4466c92259cf80c7dcc480a1efbf1b173440edd920afe237ac0eb865bf45e82128ace00d13009cab247846c053c38ce9bf5d3e96abb48543f87c2a5c737f6770a3f7586072cf26ce354f2d1068ac04bccd54122efd44a4f556f9fc903a7605cf18f6254b9adcf6a898694ad9649778b06376d3f098179875db99de4e6c2cd5f3512ff47ba0ba6ea70b88373f3e11f717f9891d7e254d52a3f0bad9b1d897fcc9cda351fbe69bcd5e7b4a247a92ce716beedffb1ff2462b6
[2020-01-31 15:53:31.566] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated sk_ai: 7b97289ae04d95750fe9f2828d9fda5b62d1772d6168f040e48ab01d7babb3e56cb40f04627678a28fcbfe33949f49978699f5e8f7b03b65551af954117600c5
[2020-01-31 15:53:31.566] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated sk_ar: f7661e2cd362e1b2894f8b0cc90b9d0f0c15bbaa8eac056fcc2a0639dd1ad0312ce13bb9562835b10b6f2e0c7587506fa6cba89085ccba99236971f73895cb73
[2020-01-31 15:53:31.566] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated sk_ei: b2baecb8414b600eca186290a76e10f12715fbc78f62472cbefc87f81f7786ff
[2020-01-31 15:53:31.566] [DEBUG  ] IKE_SA: 05ccc375c7c8334f. Generated sk_er: 04ae70a896cbae750d43cbecfc690c44aa9dc1b6b0797238813e709a1fe5bdaa
[2020-01-31 15:53:31.567] [INFO   ] IKE_SA: 05ccc375c7c8334f. Created CHILD_SA (ad8b91bc, 979b590d)

``` 
