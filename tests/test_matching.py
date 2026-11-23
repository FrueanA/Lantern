import unittest

from lantern.rules import Detection, FieldMatcher, RuleError


def match(key, values, fields):
    return FieldMatcher(key, values).matches(fields)


class FieldMatcherTests(unittest.TestCase):
    def test_equality_is_case_insensitive(self):
        self.assertTrue(match("User", "corp\\j.alvarez", {"User": "CORP\\J.Alvarez"}))
        self.assertFalse(match("User|cased", "corp\\j.alvarez", {"User": "CORP\\J.Alvarez"}))

    def test_list_values_are_or(self):
        self.assertTrue(match("EventID", [4728, 4732], {"EventID": 4732}))
        self.assertFalse(match("EventID", [4728, 4732], {"EventID": 4720}))

    def test_numbers_and_strings_compare(self):
        self.assertTrue(match("LogonType", 10, {"LogonType": "10"}))
        self.assertTrue(match("EventID", "4625", {"EventID": 4625}))

    def test_hex_values_compare_numerically(self):
        # YAML reads an unquoted 0x17 as the integer 23.
        self.assertTrue(match("TicketEncryptionType", 23, {"TicketEncryptionType": "0x17"}))
        self.assertTrue(match("GrantedAccess", "0x1010", {"GrantedAccess": "0x1010"}))

    def test_string_modifiers(self):
        fields = {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}
        self.assertTrue(match("Image|endswith", "\\powershell.exe", fields))
        self.assertTrue(match("Image|startswith", "c:\\windows\\", fields))
        self.assertTrue(match("Image|contains", "PowerShell\\v1.0", fields))
        self.assertFalse(match("Image|endswith", "\\pwsh.exe", fields))

    def test_all_modifier(self):
        fields = {"CommandLine": "vssadmin.exe delete shadows /all /quiet"}
        self.assertTrue(match("CommandLine|contains|all", ["vssadmin", "delete", "shadows"], fields))
        self.assertFalse(match("CommandLine|contains|all", ["vssadmin", "resize"], fields))

    def test_regex(self):
        fields = {"CommandLine": "powershell -NoP -EnC SQBFAFgAIAAoAE4AZQB3AC0A"}
        self.assertTrue(match("CommandLine|re", r"\s-enc\s+[A-Za-z0-9+/=]{16,}", fields))

    def test_wildcards(self):
        self.assertTrue(match("TaskName", "\\Microsoft\\*", {"TaskName": "\\Microsoft\\Windows\\Defrag"}))

    def test_cidr(self):
        private = ["10.0.0.0/8", "192.168.0.0/16"]
        self.assertTrue(match("IpAddress|cidr", private, {"IpAddress": "10.4.2.1"}))
        self.assertTrue(match("IpAddress|cidr", private, {"IpAddress": "::ffff:192.168.1.5"}))
        self.assertFalse(match("IpAddress|cidr", private, {"IpAddress": "203.0.113.45"}))
        self.assertFalse(match("IpAddress|cidr", private, {"IpAddress": "-"}))

    def test_numeric_comparisons(self):
        self.assertTrue(match("Count|gte", 5, {"Count": "5"}))
        self.assertFalse(match("Count|gt", 5, {"Count": "5"}))
        self.assertTrue(match("Count|lt", "0x10", {"Count": 15}))

    def test_null_and_exists(self):
        self.assertTrue(match("IpAddress", None, {}))
        self.assertTrue(match("IpAddress", [None, "-"], {"IpAddress": "-"}))
        self.assertFalse(match("IpAddress", None, {"IpAddress": "10.0.0.1"}))
        self.assertTrue(match("ParentImage|exists", True, {"ParentImage": "x"}))
        self.assertTrue(match("ParentImage|exists", False, {}))

    def test_missing_field_never_matches_a_value(self):
        self.assertFalse(match("CommandLine|contains", "vssadmin", {}))

    def test_unknown_modifier(self):
        with self.assertRaises(RuleError):
            FieldMatcher("Image|endwith", "x")


class DetectionTests(unittest.TestCase):
    def test_list_of_maps_is_or(self):
        detection = Detection({
            "proc": [
                {"EventID": 4688, "NewProcessName|endswith": "\\cmd.exe"},
                {"EventID": 1, "Image|endswith": "\\cmd.exe"},
            ],
            "condition": "proc",
        })
        self.assertTrue(detection.matches({"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe"}))
        self.assertTrue(detection.matches({"EventID": 4688, "NewProcessName": "C:\\Windows\\System32\\cmd.exe"}))
        self.assertFalse(detection.matches({"EventID": 4688, "Image": "C:\\Windows\\System32\\cmd.exe"}))

    def test_keywords(self):
        detection = Detection({"words": ["mimikatz", "sekurlsa"], "condition": "words"})
        self.assertTrue(detection.matches({"CommandLine": "run Sekurlsa::logonpasswords"}))
        self.assertFalse(detection.matches({"CommandLine": "notepad.exe"}))

    def test_filters(self):
        detection = Detection({
            "access": {"TargetImage|endswith": "\\lsass.exe"},
            "filter_defender": {"SourceImage|startswith": "C:\\ProgramData\\Microsoft\\Windows Defender\\"},
            "condition": "access and not 1 of filter_*",
        })
        self.assertFalse(detection.matches({
            "TargetImage": "C:\\Windows\\system32\\lsass.exe",
            "SourceImage": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe",
        }))
        # The same file name somewhere else is not trusted.
        self.assertTrue(detection.matches({
            "TargetImage": "C:\\Windows\\system32\\lsass.exe",
            "SourceImage": "C:\\Users\\Public\\MsMpEng.exe",
        }))

    def test_condition_must_reference_real_selections(self):
        with self.assertRaises(RuleError):
            Detection({"sel": {"EventID": 1}, "condition": "sel and typo"})


if __name__ == "__main__":
    unittest.main()
