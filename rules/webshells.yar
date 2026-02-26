rule WEBSHELL_PHP_Eval {
    meta:
        description = "Detects PHP webshell eval/base64 patterns"
        severity = "high"
        category = "webshell"
        false_positive_risk = "low"
    strings:
        $php1 = "eval(base64_decode(" ascii nocase
        $php2 = "eval(gzinflate(" ascii nocase
        $php3 = "eval(gzuncompress(" ascii nocase
        $php4 = "eval(str_rot13(" ascii nocase
        $php5 = "assert(base64_decode(" ascii nocase
    condition:
        any of them
}

rule WEBSHELL_PHP_System {
    meta:
        description = "Detects PHP webshell command execution patterns"
        severity = "critical"
        category = "webshell"
        false_positive_risk = "very_low"
    strings:
        $cmd1 = "system($_GET" ascii
        $cmd2 = "system($_POST" ascii
        $cmd3 = "system($_REQUEST" ascii
        $cmd4 = "shell_exec($_GET" ascii
        $cmd5 = "shell_exec($_POST" ascii
        $cmd6 = "passthru($_GET" ascii
        $cmd7 = "passthru($_POST" ascii
        $cmd8 = "exec($_GET" ascii
        $cmd9 = "exec($_POST" ascii
        $cmd10 = "popen($_GET" ascii
    condition:
        any of them
}

rule WEBSHELL_Python_Exec {
    meta:
        description = "Detects Python webshell exec/compile patterns"
        severity = "high"
        category = "webshell"
        false_positive_risk = "low"
    strings:
        $py1 = "exec(compile(" ascii
        $py2 = "exec(base64.b64decode(" ascii
        $py3 = "__import__('os').system(" ascii
        $py4 = "exec(marshal.loads(" ascii
    condition:
        any of them
}

rule WEBSHELL_Python_Request_Exec {
    meta:
        description = "Detects Python code execution via web request parameters"
        severity = "critical"
        category = "webshell"
        false_positive_risk = "very_low"
    strings:
        $sub1 = "subprocess.call(request" ascii
        $sub2 = "subprocess.Popen(request" ascii
        $os1  = "os.popen(request" ascii
        $os2  = "os.system(request" ascii
    condition:
        any of them
}

rule WEBSHELL_Generic_Indicators {
    meta:
        description = "Detects generic webshell indicator patterns — requires 3 matches"
        severity = "medium"
        category = "webshell"
        false_positive_risk = "medium"
    strings:
        $ind1 = "FilesMan" ascii nocase
        $ind2 = "WSO " ascii
        $ind3 = "c99shell" ascii nocase
        $ind4 = "r57shell" ascii nocase
        $ind5 = "b374k" ascii nocase
        $ind6 = "p0wny" ascii nocase
        $ind7 = "webshell" ascii nocase
        $ind8 = "cmd.php" ascii nocase
    condition:
        3 of them
}
