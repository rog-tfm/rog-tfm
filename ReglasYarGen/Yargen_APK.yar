/*
   YARA Rule Set
   Author: RamonOrtiz
   Date: 2021-08-06
   Identifier: APK
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_44ea6e68941e2f3716ecaa178775d5e81008edc7a969d40c90baf85a862a7a57 {
   meta:
      description = "APK - file 44ea6e68941e2f3716ecaa178775d5e81008edc7a969d40c90baf85a862a7a57.apk"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "44ea6e68941e2f3716ecaa178775d5e81008edc7a969d40c90baf85a862a7a57"
   strings:
      $s1 = "res/drawable/design_password_eye.xml" fullword ascii
      $s2 = "android@android.com" fullword ascii
      $s3 = "res/drawable/design_password_eye.xmlPK" fullword ascii
      $s4 = "res/layout/test_toolbar_elevation.xmlcf" fullword ascii
      $s5 = "res/layout/test_toolbar_elevation.xmlPK" fullword ascii
      $s6 = "res/drawable/$avd_hide_password__2.xml" fullword ascii
      $s7 = "res/drawable/$avd_hide_password__1.xml" fullword ascii
      $s8 = "res/drawable/$avd_show_password__2.xml" fullword ascii
      $s9 = "res/drawable/$avd_show_password__1.xml" fullword ascii
      $s10 = "res/drawable/avd_show_password.xml" fullword ascii
      $s11 = "res/drawable/avd_hide_password.xml" fullword ascii
      $s12 = "res/drawable/$avd_show_password__0.xml" fullword ascii
      $s13 = "res/drawable/$avd_hide_password__0.xml" fullword ascii
      $s14 = "res/layout-land/mtrl_picker_header_dialog.xmlcf" fullword ascii
      $s15 = "res/layout/mtrl_picker_header_dialog.xmlPK" fullword ascii
      $s16 = "res/layout-land/mtrl_picker_header_dialog.xmlPK" fullword ascii
      $s17 = "res/layout/mtrl_picker_header_dialog.xmlcf" fullword ascii
      $s18 = "res/xml/accessibility_service_config.xml]" fullword ascii
      $s19 = "res/animator/mtrl_btn_unelevated_state_list_anim.xmlcf" fullword ascii
      $s20 = "res/animator/mtrl_btn_unelevated_state_list_anim.xmlPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 10000KB and
      8 of them
}

rule sig_01bd75f0da798be5f162b98a7ee91be4582ed8735863f2623593d968fbd5a028 {
   meta:
      description = "APK - file 01bd75f0da798be5f162b98a7ee91be4582ed8735863f2623593d968fbd5a028.apk"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "01bd75f0da798be5f162b98a7ee91be4582ed8735863f2623593d968fbd5a028"
   strings:
      $s1 = "AkXDLLW" fullword ascii
      $s2 = "ddghetk" fullword ascii
      $s3 = "resources.arscPK" fullword ascii
      $s4 = "resources.arsc" fullword ascii
      $s5 = "res/drawable-hdpi-v4/ic_launcher.png" fullword ascii
      $s6 = "res/drawable-xhdpi-v4/ic_launcher.png" fullword ascii
      $s7 = "res/drawable-mdpi-v4/ic_launcher_round.png" fullword ascii
      $s8 = "res/drawable-xxhdpi-v4/ic_launcher_round.png" fullword ascii
      $s9 = "res/drawable-xxhdpi-v4/ic_launcher.png" fullword ascii
      $s10 = "res/layout/main.xml" fullword ascii
      $s11 = "res/drawable-hdpi-v4/ic_launcher_round.png" fullword ascii
      $s12 = "res/drawable-xhdpi-v4/ic_launcher_round.png" fullword ascii
      $s13 = "res/drawable-mdpi-v4/ic_launcher.png" fullword ascii
      $s14 = "mw:\\3>f" fullword ascii
      $s15 = "X<$EftP" fullword ascii
      $s16 = "Bwvlll6" fullword ascii
      $s17 = "jnhakt" fullword ascii
      $s18 = "a+\\r- `" fullword ascii
      $s19 = "bAdHAK0" fullword ascii
      $s20 = "Vg71* " fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      8 of them
}

rule sig_4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625c {
   meta:
      description = "APK - file 4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625c.apk"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625c"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s2 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:xmp=\"http://ns.adobe.com/xa" ascii
      $s3 = "assets/yandexnavi/sound/common/Command.ogg" fullword ascii
      $s4 = "assets/view3d/defaultExecution/Mei-Calibration.xml" fullword ascii
      $s5 = "ggfgfg" fullword ascii /* reversed goodware string 'gfgfgg' */
      $s6 = "assets/mkdirtemplate/albumart.jpg" fullword ascii
      $s7 = "assets/secretKey.ogg" fullword ascii
      $s8 = "assets/zxing/images/search-book-contents.jpg" fullword ascii
      $s9 = "assets/texts-zh-hant/make_more_headline_employee_of_the_day_china_traditional_01.png" fullword ascii
      $s10 = "assets/texts-zh-hans/make_more_headline_employee_of_the_day_china_simplified_01.png" fullword ascii
      $s11 = "assets/yandexnavi/sound/common/Command.oggPK" fullword ascii
      $s12 = "assets/texts-kr/make_more_headline_coin_rain_korea_01.png" fullword ascii
      $s13 = "ID=\"2701FF79EC54DCE1C77D5509D2846376\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>+" fullword ascii
      $s14 = "assets/view3d/defaultExecution/Mei-Calibration.xmlPK" fullword ascii
      $s15 = "assets/texts-zh-hant/make_more_headline_coin_rain_china_traditional_01.png" fullword ascii
      $s16 = "assets/texts-zh-hans/make_more_headline_coin_rain_china_simplified_01.png" fullword ascii
      $s17 = "zzzFFF" fullword ascii /* reversed goodware string 'FFFzzz' */
      $s18 = "56:27        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii
      $s19 = "assets/mkdirtemplate/albumart.jpgPK" fullword ascii
      $s20 = "assets/mkdirtemplate/silence.mp3" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 11000KB and
      8 of them
}

rule b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3 {
   meta:
      description = "APK - file b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3.apk"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s2 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:xmp=\"http://ns.adobe.com/xa" ascii
      $s3 = "jsr330_inject/Jsr330_inject.gwt.xmlU" fullword ascii
      $s4 = "javax/inject/Inject.gwt.xmlPK" fullword ascii
      $s5 = "third_party/java_src/jsr330_inject/Jsr330_inject.gwt.xmlU" fullword ascii
      $s6 = "jsr330_inject/Jsr330_inject.gwt.xmlPK" fullword ascii
      $s7 = "third_party/java_src/jsr330_inject/Jsr330_inject.gwt.xmlPK" fullword ascii
      $s8 = "javax/inject/Inject.gwt.xml5" fullword ascii
      $s9 = "assets/yandexnavi/sound/common/Command.ogg" fullword ascii
      $s10 = "assets/view3d/defaultExecution/Mei-Calibration.xml" fullword ascii
      $s11 = "KKres/drawable-xhdpi/common_google_signin_btn_text_dark_normal_background.png" fullword ascii
      $s12 = "00res/color/common_google_signin_btn_text_dark.xml" fullword ascii
      $s13 = "::res/drawable/common_google_signin_btn_icon_dark_normal.xml" fullword ascii
      $s14 = "KKres/drawable-xhdpi/common_google_signin_btn_icon_dark_normal_background.png" fullword ascii
      $s15 = "33res/drawable/common_google_signin_btn_icon_dark.xml" fullword ascii
      $s16 = "res/drawable-xxhdpi/common_google_signin_btn_text_dark_normal_background.png" fullword ascii
      $s17 = "res/drawable-xhdpi/common_google_signin_btn_text_dark_normal_background.png" fullword ascii
      $s18 = "res/drawable-xhdpi/common_google_signin_btn_icon_dark_normal_background.png" fullword ascii
      $s19 = "res/drawable-hdpi/common_google_signin_btn_text_dark_normal_background.png" fullword ascii
      $s20 = "res/drawable-mdpi/common_google_signin_btn_icon_dark_normal_background.png" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 13000KB and
      8 of them
}

rule sig_2d1370802093457d7bb7b151278ff6fcd2e8944e56d87ffc483422bef2f6d8e2 {
   meta:
      description = "APK - file 2d1370802093457d7bb7b151278ff6fcd2e8944e56d87ffc483422bef2f6d8e2.apk"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "2d1370802093457d7bb7b151278ff6fcd2e8944e56d87ffc483422bef2f6d8e2"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s2 = "xpwwwwwww" fullword ascii /* reversed goodware string 'wwwwwwwpx' */
      $s3 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:xmp=\"http://ns.adobe.com/xa" ascii
      $s4 = "assets/yandexnavi/sound/common/Command.ogg" fullword ascii
      $s5 = "assets/view3d/defaultExecution/Mei-Calibration.xml" fullword ascii
      $s6 = "assets/zxing/images/search-book-contents.jpg" fullword ascii
      $s7 = "assets/texts-zh-hant/make_more_headline_employee_of_the_day_china_traditional_01.png" fullword ascii
      $s8 = "assets/texts-zh-hans/make_more_headline_employee_of_the_day_china_simplified_01.png" fullword ascii
      $s9 = "assets/yandexnavi/sound/common/Command.oggPK" fullword ascii
      $s10 = "assets/texts-kr/make_more_headline_coin_rain_korea_01.png" fullword ascii
      $s11 = "ID=\"2701FF79EC54DCE1C77D5509D2846376\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>+" fullword ascii
      $s12 = "assets/view3d/defaultExecution/Mei-Calibration.xmlPK" fullword ascii
      $s13 = "assets/texts-zh-hant/make_more_headline_coin_rain_china_traditional_01.png" fullword ascii
      $s14 = "assets/texts-zh-hans/make_more_headline_coin_rain_china_simplified_01.png" fullword ascii
      $s15 = "zzzFFF" fullword ascii /* reversed goodware string 'FFFzzz' */
      $s16 = "56:27        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii
      $s17 = "assets/yandexnavi/public_keys/001_public_key.peme" fullword ascii
      $s18 = "assets/xiaoying/ini/CPUConfig.ini" fullword ascii
      $s19 = "assets/xiaoying/bubbleframe/0x0900500000080001.xyt" fullword ascii
      $s20 = "assets/yandexnavi/public_keys/000_public_key.peme" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 14000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _2d1370802093457d7bb7b151278ff6fcd2e8944e56d87ffc483422bef2f6d8e2_4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cb_0 {
   meta:
      description = "APK - from files 2d1370802093457d7bb7b151278ff6fcd2e8944e56d87ffc483422bef2f6d8e2.apk, 4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625c.apk, b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3.apk"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "2d1370802093457d7bb7b151278ff6fcd2e8944e56d87ffc483422bef2f6d8e2"
      hash2 = "4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625c"
      hash3 = "b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s2 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:xmp=\"http://ns.adobe.com/xa" ascii
      $s3 = "assets/yandexnavi/sound/common/Command.ogg" fullword ascii
      $s4 = "assets/view3d/defaultExecution/Mei-Calibration.xml" fullword ascii
      $s5 = "assets/zxing/images/search-book-contents.jpg" fullword ascii
      $s6 = "assets/texts-zh-hant/make_more_headline_employee_of_the_day_china_traditional_01.png" fullword ascii
      $s7 = "assets/texts-zh-hans/make_more_headline_employee_of_the_day_china_simplified_01.png" fullword ascii
      $s8 = "assets/yandexnavi/sound/common/Command.oggPK" fullword ascii
      $s9 = "assets/texts-kr/make_more_headline_coin_rain_korea_01.png" fullword ascii
      $s10 = "ID=\"2701FF79EC54DCE1C77D5509D2846376\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>+" fullword ascii
      $s11 = "assets/view3d/defaultExecution/Mei-Calibration.xmlPK" fullword ascii
      $s12 = "assets/texts-zh-hant/make_more_headline_coin_rain_china_traditional_01.png" fullword ascii
      $s13 = "assets/texts-zh-hans/make_more_headline_coin_rain_china_simplified_01.png" fullword ascii
      $s14 = "zzzFFF" fullword ascii /* reversed goodware string 'FFFzzz' */
      $s15 = "56:27        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmpMM" ascii
      $s16 = "assets/yandexnavi/public_keys/001_public_key.peme" fullword ascii
      $s17 = "assets/xiaoying/ini/CPUConfig.ini" fullword ascii
      $s18 = "assets/xiaoying/bubbleframe/0x0900500000080001.xyt" fullword ascii
      $s19 = "assets/yandexnavi/public_keys/000_public_key.peme" fullword ascii
      $s20 = "assets/yandexnavi/sound/common/Yes.ogg" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625c_b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a_1 {
   meta:
      description = "APK - from files 4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625c.apk, b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3.apk"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625c"
      hash2 = "b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3"
   strings:
      $s1 = "assets/mkdirtemplate/albumart.jpg" fullword ascii
      $s2 = "assets/secretKey.ogg" fullword ascii
      $s3 = "assets/mkdirtemplate/albumart.jpgPK" fullword ascii
      $s4 = "assets/mkdirtemplate/silence.mp3" fullword ascii
      $s5 = "assets/mkdirtemplate/silence.mp3PK" fullword ascii
      $s6 = "assets/secretKey.oggPK" fullword ascii
      $s7 = "assets/panel/emojipanel-config.xml" fullword ascii
      $s8 = "assets/panel/emojipanel-config-jifu.xml" fullword ascii
      $s9 = "assets/SecretSheet.png" fullword ascii
      $s10 = "assets/square01_001-hd.png" fullword ascii
      $s11 = "assets/magicExplosion.ogg" fullword ascii
      $s12 = "assets/SecretSheet.pngPK" fullword ascii
      $s13 = "assets/newemoji/2_09.png" fullword ascii
      $s14 = "assets/AchievementsDescMD.plistPK" fullword ascii
      $s15 = "assets/newemoji/2_07.png" fullword ascii
      $s16 = "assets/panel/emojipanel-config.xmlPK" fullword ascii
      $s17 = "assets/panel/emojipanel-config-jifu.xmlPK" fullword ascii
      $s18 = "assets/AchievementsDescMD.plist" fullword ascii
      $s19 = "assets/reward01.ogg" fullword ascii
      $s20 = "assets/achievement_01.ogg" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _44ea6e68941e2f3716ecaa178775d5e81008edc7a969d40c90baf85a862a7a57_2d1370802093457d7bb7b151278ff6fcd2e8944e56d87ffc483422bef2_2 {
   meta:
      description = "APK - from files 44ea6e68941e2f3716ecaa178775d5e81008edc7a969d40c90baf85a862a7a57.apk, 2d1370802093457d7bb7b151278ff6fcd2e8944e56d87ffc483422bef2f6d8e2.apk, 4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625c.apk, b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3.apk"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "44ea6e68941e2f3716ecaa178775d5e81008edc7a969d40c90baf85a862a7a57"
      hash2 = "2d1370802093457d7bb7b151278ff6fcd2e8944e56d87ffc483422bef2f6d8e2"
      hash3 = "4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625c"
      hash4 = "b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3"
   strings:
      $s1 = "res/mipmap-xxxhdpi/ic_launcher.png" fullword ascii
      $s2 = "res/mipmap-hdpi/ic_launcher_round.png" fullword ascii
      $s3 = "res/mipmap-xhdpi/ic_launcher.png" fullword ascii
      $s4 = "res/mipmap-mdpi/ic_launcher.png" fullword ascii
      $s5 = "res/mipmap-mdpi/ic_launcher_round.png" fullword ascii
      $s6 = "AndroidManifest.xmlPK" fullword ascii
      $s7 = "res/mipmap-hdpi/ic_launcher.png" fullword ascii
      $s8 = "res/mipmap-xxhdpi/ic_launcher_round.png" fullword ascii
      $s9 = "res/mipmap-xxxhdpi/ic_launcher_round.png" fullword ascii
      $s10 = "res/mipmap-xxhdpi/ic_launcher.png" fullword ascii
      $s11 = "res/mipmap-xhdpi/ic_launcher_round.png" fullword ascii
      $s12 = "classes.dex," fullword ascii
      $s13 = "res/mipmap-xxxhdpi/ic_launcher_round.pngPK" fullword ascii
      $s14 = "res/mipmap-mdpi/ic_launcher_round.pngPK" fullword ascii
      $s15 = "res/mipmap-mdpi/ic_launcher.pngPK" fullword ascii
      $s16 = "res/mipmap-hdpi/ic_launcher.pngPK" fullword ascii
      $s17 = "res/mipmap-xxhdpi/ic_launcher.pngPK" fullword ascii
      $s18 = "res/mipmap-xhdpi/ic_launcher.pngPK" fullword ascii
      $s19 = "res/mipmap-xhdpi/ic_launcher_round.pngPK" fullword ascii
      $s20 = "res/mipmap-xxhdpi/ic_launcher_round.pngPK" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _44ea6e68941e2f3716ecaa178775d5e81008edc7a969d40c90baf85a862a7a57_b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a_3 {
   meta:
      description = "APK - from files 44ea6e68941e2f3716ecaa178775d5e81008edc7a969d40c90baf85a862a7a57.apk, b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3.apk"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "44ea6e68941e2f3716ecaa178775d5e81008edc7a969d40c90baf85a862a7a57"
      hash2 = "b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3"
   strings:
      $s1 = "res/drawable/$ic_launcher_foreground__0.xml" fullword ascii
      $s2 = "res/drawable/$ic_launcher_foreground__0.xmlPK" fullword ascii
      $s3 = "res/mipmap-anydpi-v26/ic_launcher.xmlPK" fullword ascii
      $s4 = "cyV`EVbeVaUVcu" fullword ascii
      $s5 = "res/drawable/ic_launcher_foreground.xmlPK" fullword ascii
      $s6 = "res/drawable/ic_launcher_background.xmlcf" fullword ascii
      $s7 = "res/mipmap-anydpi-v26/ic_launcher_round.xmlPK" fullword ascii
      $s8 = "res/drawable/ic_launcher_foreground.xmlcf" fullword ascii
      $s9 = "res/drawable/ic_launcher_background.xmlPK" fullword ascii
      $s10 = ">r\\R/~" fullword ascii
      $s11 = "q=7p#7q3" fullword ascii
      $s12 = "q;wp'wq7" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _01bd75f0da798be5f162b98a7ee91be4582ed8735863f2623593d968fbd5a028_2d1370802093457d7bb7b151278ff6fcd2e8944e56d87ffc483422bef2_4 {
   meta:
      description = "APK - from files 01bd75f0da798be5f162b98a7ee91be4582ed8735863f2623593d968fbd5a028.apk, 2d1370802093457d7bb7b151278ff6fcd2e8944e56d87ffc483422bef2f6d8e2.apk, 4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625c.apk, b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3.apk"
      author = "RamonOrtiz"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-08-06"
      hash1 = "01bd75f0da798be5f162b98a7ee91be4582ed8735863f2623593d968fbd5a028"
      hash2 = "2d1370802093457d7bb7b151278ff6fcd2e8944e56d87ffc483422bef2f6d8e2"
      hash3 = "4b0f9cbdd2d6a2d9ebc4123f3630635a38b0f4aa1a47c5ea77617e33cbc1625c"
      hash4 = "b88e7421bc61f4ce20c0694418fc97c1e77cfd3f2053857f87cc47512a55c3d3"
   strings:
      $s1 = "Vg71* " fullword ascii
      $s2 = "META-INF/CERT.RSAPK" fullword ascii
      $s3 = "META-INF/CERT.RSA3hb[" fullword ascii
      $s4 = "META-INF/CERT.SF" fullword ascii
      $s5 = "META-INF/CERT.SFPK" fullword ascii
      $s6 = "k`a`ddi`hllb" fullword ascii
      $s7 = "klj`nh" fullword ascii
      $s8 = "fa5`fd" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 14000KB and ( all of them )
      ) or ( all of them )
}

