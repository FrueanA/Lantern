import unittest

from lantern.conditions import ConditionError, compile_condition


def evaluate(text, truth):
    return compile_condition(text, truth)(lambda name: truth[name])


class ConditionTests(unittest.TestCase):
    def test_single_selection(self):
        self.assertTrue(evaluate("sel", {"sel": True}))
        self.assertFalse(evaluate("sel", {"sel": False}))

    def test_and_binds_tighter_than_or(self):
        truth = {"a": True, "b": False, "c": False}
        self.assertTrue(evaluate("a or b and c", truth))
        self.assertFalse(evaluate("(a or b) and c", truth))

    def test_not(self):
        self.assertTrue(evaluate("a and not b", {"a": True, "b": False}))
        self.assertFalse(evaluate("not not b", {"b": False}))

    def test_keywords_are_case_insensitive(self):
        self.assertTrue(evaluate("a AND NOT b", {"a": True, "b": False}))

    def test_one_of_pattern(self):
        truth = {"sel": True, "filter_a": False, "filter_b": True}
        self.assertFalse(evaluate("sel and not 1 of filter_*", truth))
        self.assertTrue(evaluate("sel and not all of filter_*", truth))

    def test_them_skips_underscore_names(self):
        truth = {"a": True, "b": True, "_helper": False}
        self.assertTrue(evaluate("all of them", truth))
        self.assertTrue(evaluate("any of them", {"a": False, "b": True}))

    def test_short_circuit(self):
        calls = []

        def lookup(name):
            calls.append(name)
            return False

        compile_condition("a and b", ["a", "b"])(lookup)
        self.assertEqual(calls, ["a"])

    def test_errors(self):
        for text in ["", "a and", "a b", "(a", "missing", "1 of nothing_*", "a or or b", "a*"]:
            with self.subTest(text=text), self.assertRaises(ConditionError):
                compile_condition(text, ["a", "b"])


if __name__ == "__main__":
    unittest.main()
