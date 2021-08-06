
/*
   YARA Rule Set
   Author: Ramon Ortiz
   Date: 2021-08-06
   Identifier: APK
   
*/

/* Rule Set ----------------------------------------------------------------- */

rule tight__home_kali_Descargas_MuestrasMalwareTFM_APK_4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625capk {
 strings:
  $a_2 = { 558b5b5b66641dd78c89bf92a3159374 }
  $a_3 = { 558b79bfe247c051744fc443ee718754 }
  $a_4 = { 558bc893ba65e17bab37ee5bff64f7dd }
  $a_5 = { 558be1a550a80e98c92fdf0898296095 }
  $a_6 = { 558b37d139f547fbd0e979092bcce4ed }
  $a_7 = { 558bd3cc7e0aabffec3e6627ab4e81b5 }
  $a_8 = { 558b07b0a090d2f8903e289176747210 }
  $a_9 = { 558ba6f969c3aafd2f374ffdbdb62aef }
  $a_10 = { 558b21bfd3cd398c58814567b0366c06 }
  $a_11 = { 558b4126529a60097ccec524adb62263 }
  $a_12 = { 558ba6e18c4377d6f745f9c50f951995 }
  $a_13 = { 558bc1ac5873cfb635e229a970b9066e }
  $a_14 = { 558bfc4b83a974e7f0bce0dade58446f }
  $a_15 = { 558be40a47483bb9c189fbb51372e809 }
  $a_16 = { 558bd4ff38b9e89ae21677e037094924 }
  $a_17 = { 558b590a6b6e0ecacd5bbd51c1b56c0d }
  $a_18 = { 558b042f7be5585fbbed2b179ad6a0f8 }
  $a_19 = { 558bf94e620356f6b66c93615a9c81ba }
  $a_20 = { 558bc8cddda9c3555e0dbd68c4caa162 }
  $a_21 = { 558b5e890c0edc696604b94e146969bd }
  $a_22 = { 558b76ed5b2d9bd3c7f2b51f049a0a4e }
  $a_23 = { 558b49ca8eac608680582c4b52c622c6 }
  $a_24 = { 558b685bd247d54bbf6a4471a4a7c279 }
  $a_25 = { 558b772228a768b3f45bd7703926ea45 }
  $a_26 = { 558b3c613c0548732d3c728ffe2480c8 }
  $a_27 = { 558b2ce203ae91cc0ee051b64bad619f }
  $a_28 = { 558b1a094361cf67a221b5a5ef95325f }
  $a_29 = { 558b0211b986d7aaf9700ac6ccacd825 }
  $a_30 = { 558b080e53f75371a7e967ea901f3ef7 }
  $a_31 = { 558bbf54a9c5bdbc850cb4797bf9f1ac }
  $a_32 = { 558bcaa5ea776057c09a403d3d17ceca }
  $a_33 = { 558bbec712e5ab06e190c535ed4eac41 }
  $a_34 = { 558b2ff62149f704cac5b6228872f1c9 }
  $a_35 = { 558be7c8edbab06fb3d411ad1d88b0b8 }
  $a_36 = { 558b4b54526ce9b996eb8818a12c2bdb }
  $a_37 = { 558b55dde442f0b06904432205067588 }
  $a_38 = { 558b0216c77ba787fa30b358ea1aca34 }
  $a_39 = { 558ba87ee0ab41e4dd030027f0ea1c47 }
  $a_40 = { 558bc8241f883279142891abf594b6c5 }
  $a_41 = { 558b29c4b4987accb6c871d4aed9a13d }
  $a_42 = { 558b416d2fab9a634c75dfabbd51e77a }
  $a_43 = { 558b1b3df3d0f682f8633e4f33acddc6 }
  $a_44 = { 558b5fcbfffd1a45b96ac96a10ef698f }
  $a_45 = { 558bdc2f74090015c346f579cacd9b3f }
  $a_46 = { 558be723a2c5f3f7bf01b1ab5fe7dad9 }
  $a_47 = { 558baf73fa96a69ce3a9b8a317296bd2 }
  $a_48 = { 558ba5326523f8cda47e297d1afb6514 }
  $a_49 = { 558b7e4f32e368f2daa45f71ccbcea9a }
  $a_50 = { 558b276d281c1157a72563903e40dc13 }
  $a_51 = { 558b06048200888d64ed7d01292b76dd }
  $a_52 = { 558b19b28343a094cd8998222927aa69 }
  $a_53 = { 558b5842ace5bcffcd4f7e8bba212576 }
  $a_54 = { 558baee3e3f49d06a7c7e909aa1df188 }
  $a_55 = { 558ba99561981a86210cc330358c8621 }
  $a_56 = { 558b572a68829ae55abcd2856abcd25c }
  $a_57 = { 558b2a925427b5887ed1966ba716b35a }
  $a_58 = { 558b5536a0e9837af0fa06a11eb5082b }
  $a_59 = { 558b889903bad41df7465c61a0afd4df }
  $a_60 = { 558bfb66c1c52e090329e03fe9872e79 }
  $a_61 = { 558b0090d937bff94d288044a55cc0c9 }
  $a_62 = { 558b1d36c7d91dd6feb06097e535ed03 }
  $a_63 = { 558be1574b1bc808fa6a6d0800c8cfd0 }
  $a_64 = { 558ba75ee5b5133114b52a9bdec3c437 }
  $a_65 = { 558b0b4f8e9f92172eae29ead495838b }
  $a_66 = { 558beb526d34c85435135dfc0cf95676 }
  $a_67 = { 558bdb56a0b81ab11d701fb084b5f5fb }
  $a_68 = { 558bf4682aadca9a30a6d3276eef1699 }
  $a_69 = { 558bc22b06e2dc9bcab96d8dbdce163f }
  $a_70 = { 558b2cd1322c3f699cab402ba90373bc }
  $a_71 = { 558b3b87205be2c1dd4acfe03c8f2b77 }
 condition:
  any of them
}



rule tight__home_kali_Descargas_MuestrasMalwareTFM_APK_44ea6e68941e2f3716ecaa178775d5e81008edc7a969d40c90baf85a862a7a57apk {
 strings:
  $a_2 = { 558bcc5d6d2a3a96dc503266b241bf26 }
  $a_3 = { 558b8ed8a87eea56da70be4638529fbf }
  $a_4 = { 558b4706b4576d7e16c9f63f0699faff }
  $a_5 = { 558ba7551fece9f61d10cd1f9a98a603 }
  $a_6 = { 558b767ecf182a73553f0234075f3c27 }
  $a_7 = { 558bdc7b9cd27e2a23ab163f49f41c68 }
  $a_8 = { 558b5533d9132fc5f1f16c8f9b4f5045 }
  $a_9 = { 558bd3ccbdb518ebc810634555d09327 }
  $a_10 = { 558b90f4998bec31e85b54d8aae2698f }
  $a_11 = { 558ba4003e3cb866ae23a55e68b5afd4 }
  $a_12 = { 558b1145043ae3662e30331ebcf61b14 }
  $a_13 = { 558b6ac143cad1d6c437ad173ec4667e }
  $a_14 = { 558b95a829bf7e27d0434c1269e610d3 }
  $a_15 = { 558b85f966e24ff9fc92886fe5e692f1 }
  $a_16 = { 558b7b33d4ecd2dea77676b18979637d }
  $a_17 = { 558b35beca84a60b93de19036f95ebd0 }
  $a_18 = { 558b3a56a58455aaf5ce3256164b776c }
  $a_19 = { 558b0707ac01db9676922940a7cd1b03 }
  $a_20 = { 558b1a50bae7792fdad195116f00cd63 }
  $a_21 = { 558bed4d8323b7934cbe89f31417916d }
  $a_22 = { 558b81e83fa645704f79f04d9842e246 }
  $a_23 = { 558b988e930c4f89b442d181d525e2c5 }
  $a_24 = { 558b1d84eedec487e5e3fa02e193d4a8 }
  $a_25 = { 558ba4243365e9c85816b29a435ce421 }
  $a_26 = { 558bf801d942ca67e418c5e203948ac3 }
  $a_27 = { 558b98a76215bbeace4e2a74b2edb2fa }
  $a_28 = { 558b2cdd3eaa6546756eddda7233e72c }
  $a_29 = { 558b9ca11d6c3ee935ff46249a5dbaf0 }
  $a_30 = { 558b45877f30b78a460a1c36f115cd94 }
  $a_31 = { 558b2d3ffa2949ec2d9b74ca70493bf9 }
  $a_32 = { 558b58e9ec0a68fbcaeb818f024506a0 }
  $a_33 = { 558bfc1223d4cfe7c48104d8b4f88104 }
  $a_34 = { 558b63666ad399d7b519cc76fa87cc6b }
  $a_35 = { 558b806b8b3ac44c096e73fb663f5073 }
  $a_36 = { 558b0718fd8ecf48bf5f4ca201a01b03 }
  $a_37 = { 558b76d6ab97b61838b866695e2cb6de }
  $a_38 = { 558b41fb9f3e548e1853fa6a664f917d }
  $a_39 = { 558b768bc7ead1fc8ba4d5a3a94e5ff8 }
  $a_40 = { 558b1c7986f171297f28556904faedd0 }
  $a_41 = { 558b94eba916e59acbf112ed9676c0b3 }
  $a_42 = { 558ba7d3cab4a60d6e86681b0f73419b }
  $a_43 = { 558b66db7f59ab469802fbcf894dfecb }
  $a_44 = { 558bd4704d7e8d8eeaba9502d75f14b2 }
 condition:
  any of them
}



rule tight__home_kali_Descargas_MuestrasMalwareTFM_APK_b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3apk {
 strings:
  $a_2 = { 558bd7383c7894c9be9de53efd8c1f6f }
  $a_3 = { 558bd4ff38b9e89ae21677e037094924 }
  $a_4 = { 558b9d80f42f944aca811c578bd3eed1 }
  $a_5 = { 558b9d94ca25572fb8bfe6b91eff67d2 }
  $a_6 = { 558b79fe9626e6b9250dccf35717ccf3 }
  $a_7 = { 558ba6f969c3aafd2f374ffdbdb62aef }
  $a_8 = { 558b781a9a676d0f95f42cf89f6ca19d }
  $a_9 = { 558b4126529a60097ccec524adb62263 }
  $a_10 = { 558b0d3261781f179bab175ae170578f }
  $a_11 = { 558b5a533257fe57fecd544649204be5 }
  $a_12 = { 558b765cccf534966b78a2c18e7b44b5 }
  $a_13 = { 5589e5ed188a2094b07b091e51f5b857 }
  $a_14 = { 558b5e890c0edc696604b94e146969bd }
  $a_15 = { 558b76ed5b2d9bd3c7f2b51f049a0a4e }
  $a_16 = { 558bb10787bac26875651e7baad83758 }
  $a_17 = { 558b49ca8eac608680582c4b52c622c6 }
  $a_18 = { 558b1385539f17da10b1a7bd04bca3d7 }
  $a_19 = { 558ba72eb3d38cf6172c2f69d8728b12 }
  $a_20 = { 558b37d300058909a55e03c6f5b24396 }
  $a_21 = { 558bafceef9b4ea65fd3f3c70f31cca2 }
  $a_22 = { 558b0c4cb5d283ef430d0fa47273d774 }
  $a_23 = { 558bfc73fbc22d4f594507e41b8a7c0c }
  $a_24 = { 558bbec712e5ab06e190c535ed4eac41 }
  $a_25 = { 558b91a4fee9ba307a99bda444889e0f }
  $a_26 = { 558b2ff62149f704cac5b6228872f1c9 }
  $a_27 = { 558be7c8edbab06fb3d411ad1d88b0b8 }
  $a_28 = { 558b4b54526ce9b996eb8818a12c2bdb }
  $a_29 = { 558b92c4c92307e0efe8fa286e19682d }
  $a_30 = { 558b55dde442f0b06904432205067588 }
  $a_31 = { 558b59f28cbe825df5161e4cfcbb2da8 }
  $a_32 = { 558ba87ee0ab41e4dd030027f0ea1c47 }
  $a_33 = { 558bfe91edfebf92bba182b3d10e2cfb }
  $a_34 = { 558bd168315afc5fe77b5e5fdfef797f }
  $a_35 = { 558bb10c653af4a544e3afac820f2020 }
  $a_36 = { 558b500a58dd78cacbf59e54ec32d48e }
  $a_37 = { 558baa1bb2e49f9bc719b2c1c694758d }
  $a_38 = { 558b4877cc0afae8e7af4bd6595e2e00 }
  $a_39 = { 558b6c8517f33a596c126bb25669a428 }
  $a_40 = { 558bbfe87dfb11a133099cd562de5399 }
  $a_41 = { 558bfc9dcc91bfe8343a4e06b63a6603 }
  $a_42 = { 558b2fb8616466f7591d0e039319de62 }
  $a_43 = { 558bd42de1548b412de3d4f9d5e8cd15 }
  $a_44 = { 558b52b0a9445d10ae0d89631d309da8 }
  $a_45 = { 558bbe2c8c874d847376289cb3433246 }
  $a_46 = { 558bae199e2b38c9b8fd66ed90ea622e }
  $a_47 = { 558b2a925427b5887ed1966ba716b35a }
  $a_48 = { 558b2a526416c86a335267d5fa0e5a8f }
  $a_49 = { 558bbb7a63a2b68da6d9b56daedb98a8 }
  $a_50 = { 558b4ed746aae5a446b9cf9a55a7b3b2 }
  $a_51 = { 558bfb66c1c52e090329e03fe9872e79 }
  $a_52 = { 558b0090d937bff94d288044a55cc0c9 }
  $a_53 = { 558b0c845636a77051462b79aec864e5 }
  $a_54 = { 558be76eac3ebaf0edda3f6ff6f19c8c }
  $a_55 = { 558ba1504f338ecbbce0326c9e4b0a2e }
  $a_56 = { 558b14a31c8de8c35cf6f386bce3f42e }
  $a_57 = { 558b8f1284299ee213545c03d32cae92 }
  $a_58 = { 558bf1fa0508b1a7fe42547db7ec4bbb }
  $a_59 = { 558bd7ca7e9a0d7665e47ddaea1bf08b }
  $a_60 = { 558b2cd1322c3f699cab402ba90373bc }
  $a_61 = { 558b06048200888d64ed7d01292b76dd }
 condition:
  any of them
}


