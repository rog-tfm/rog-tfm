rule tight__home_kali_Descargas_MuestrasMalwareTFM_EXE_f949b78b040cbfc95aafb50ef30ac3e8c16771c6b926b6f8f1efe44a1f437d51exe {
 strings:
  $a_2 = { 558b65531c5c6a2623985c6babbc0ee6 }
 condition:
  2 of them
}
