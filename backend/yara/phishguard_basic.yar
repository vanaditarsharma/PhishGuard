rule Suspicious_Powershell_Download_Strings
{
    meta:
        description = "Heuristic string rule for common script download patterns; not a malware signature database"
        author = "PhishGuard project"
    strings:
        $a = "DownloadString" nocase
        $b = "Invoke-WebRequest" nocase
        $c = "FromBase64String" nocase
    condition:
        2 of them
}
rule Office_Macro_AutoExec_Indicators
{
    meta:
        description = "Looks for common Office macro auto-execution identifiers"
    strings:
        $a = "AutoOpen" ascii nocase
        $b = "Document_Open" ascii nocase
        $c = "Workbook_Open" ascii nocase
    condition:
        any of them
}
