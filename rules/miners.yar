rule MINER_Stratum_Protocol {
    meta:
        description = "Detects stratum mining protocol strings"
        severity = "high"
        category = "cryptominer"
        false_positive_risk = "low"
    strings:
        $s1 = "stratum+tcp://" ascii nocase
        $s2 = "stratum+ssl://" ascii nocase
        $s3 = "stratum2+tcp://" ascii nocase
        $s4 = "mining.subscribe" ascii
        $s5 = "mining.authorize" ascii
        $s6 = "mining.submit" ascii
    condition:
        any of them
}

rule MINER_Known_Binaries {
    meta:
        description = "Detects known cryptominer binary strings — requires 2 indicators"
        severity = "high"
        category = "cryptominer"
        false_positive_risk = "medium"
    strings:
        $bin1 = "xmrig" ascii nocase
        $bin2 = "ethminer" ascii nocase
        $bin3 = "nbminer" ascii nocase
        $bin4 = "phoenixminer" ascii nocase
        $bin5 = "cpuminer" ascii nocase
        $bin6 = "cgminer" ascii nocase
        $bin7 = "bfgminer" ascii nocase
        $opt1 = "--threads" ascii
        $opt2 = "donate-level" ascii
        $opt3 = "--cpu-priority" ascii
        $opt4 = "hashrate" ascii nocase
    condition:
        2 of ($bin*) or
        (1 of ($bin*) and 1 of ($opt*))
}

rule MINER_Pool_Domains {
    meta:
        description = "Detects mining pool domain strings"
        severity = "medium"
        category = "cryptominer"
        false_positive_risk = "low"
    strings:
        $pool1 = "pool.minexmr" ascii nocase
        $pool2 = "xmrpool.eu" ascii nocase
        $pool3 = "monerohash" ascii nocase
        $pool4 = "nanopool.org" ascii nocase
        $pool5 = "hashvault.pro" ascii nocase
        $pool6 = "supportxmr.com" ascii nocase
        $pool7 = "herominers.com" ascii nocase
        $pool8 = "2miners.com" ascii nocase
        $pool9 = "minergate.com" ascii nocase
    condition:
        any of them
}
