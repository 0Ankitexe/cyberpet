rule RANSOM_Note_Strings {
    meta:
        description = "Detects common ransomware note strings — requires 3 indicators"
        severity = "high"
        category = "ransomware"
        false_positive_risk = "low"
    strings:
        $r1 = "your files have been encrypted" ascii nocase
        $r2 = "your personal files are encrypted" ascii nocase
        $r3 = "to decrypt your files" ascii nocase
        $r4 = "send bitcoin" ascii nocase
        $r5 = "pay within" ascii nocase
        $r6 = "decryption key" ascii nocase
        $r7 = "wallet address" ascii nocase
        $r8 = "your files will be lost" ascii nocase
    condition:
        3 of them
}

rule RANSOM_Known_Families {
    meta:
        description = "Detects known ransomware family strings — requires 2 matches"
        severity = "critical"
        category = "ransomware"
        false_positive_risk = "low"
    strings:
        $fam1 = "WannaCry" ascii nocase
        $fam2 = "CryptoLocker" ascii nocase
        $fam3 = "GandCrab" ascii nocase
        $fam4 = "REvil" ascii nocase
        $fam5 = "DarkSide" ascii nocase
        $fam6 = "LockBit" ascii nocase
        $fam7 = "BlackMatter" ascii nocase
        $fam8 = "Conti" ascii nocase
    condition:
        2 of them
}

rule RANSOM_Bitcoin_Payment {
    meta:
        description = "Detects Bitcoin payment instructions common in ransomware"
        severity = "high"
        category = "ransomware"
        false_positive_risk = "low"
    strings:
        $btc_addr = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $btc_word = "bitcoin" ascii nocase
        $ransom1 = "your files have been encrypted" ascii nocase
        $ransom2 = "pay the ransom" ascii nocase
        $ransom3 = "decrypt your files" ascii nocase
        $ransom4 = "send payment" ascii nocase
    condition:
        $btc_addr and $btc_word and 1 of ($ransom*)
}
