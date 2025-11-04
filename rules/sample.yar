rule Suspicious_EXE
{
    meta:
        description = "Flags Windows PE files as suspicious"
        author = "example"
    strings:
        $mz = { 4D 5A }
    condition:
        uint16(0) == 0x5A4D and $mz
}


