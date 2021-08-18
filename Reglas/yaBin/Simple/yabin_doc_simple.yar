rule tight___5ea7a724d99fab3f05f50dccd57db59451334ac8640c532d426df319dad55c9epdf {
 strings:
  $a_2 = { 558bb72e55c9bab3aa225e15d2f9c3ed }
  $a_3 = { 558b5a8a48a7ae929eae67b4198538a3 }
  $a_4 = { 558ba8b18a510c368536c4628c1bb70e }
  $a_5 = { 558b94f12adf63d6e1ac5e23a4577c35 }
  $a_6 = { 558b8c77cce5f7b270be8992a05abc0a }
 condition:
  5 of them
}
