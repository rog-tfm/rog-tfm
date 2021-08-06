rule tight__home_kali_Descargas_MuestrasMalwareTFM_JS_d1293e4327bb33ec6671a37232aaa648949018b263e0443ac9cc41a278601b02jar {
 strings:
  $a_2 = { 558b5a26a0ad2da43dbefe4cfa5656cf }
  $a_3 = { 558bc12040802510386d33c088453020 }
  $a_4 = { 558b1fc17d5afc28dea2c5d3b85b8b4f }
 condition:
  any of them
}



