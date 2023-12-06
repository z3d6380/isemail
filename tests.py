# File: tests.py
# Written by: Luis Moraguez
# Date: 2023-12-06
# Description: Unit tests for is_email.py

import unittest
import xml.etree.ElementTree as ET
from is_email import *

class TestIsEmail(unittest.TestCase):

    def boldRed(self, string):
        return f'\033[1;31m{string}\033[0m'
    
    def boldGreen(self, string):
        return f'\033[1;32m{string}\033[0m'
    
    def boldBlue(self, string):
        return f'\033[1;34m{string}\033[0m'
    
    def boldWhite(self, string):
        return f'\033[1;37m{string}\033[0m'
    
    def yellow(self, string):
        return f'\033[33m{string}\033[0m'
    
    def cyan(self, string):
        return f'\033[36m{string}\033[0m'

    def setUp(self):
        tree = ET.parse('./tests/tests.xml')
        self.tests = tree.getroot().findall('test')
        self.results = {}
        self.pass_count = 0
        self.fail_count = 0

    def test_is_email(self):
        for test in self.tests:
            #print(ET.tostring(test, encoding='utf8').decode('utf8'))
            test_id = test.get('id')
            address = test.find('address').text or ""
            expected_result = test.find('diagnosis').text
            email_validity = is_email(address, True, True)
            result = result_codes.get(email_validity, "Unknown result code")
            try:
                self.assertEqual(result, expected_result)
                self.results[test_id] = f'{self.boldGreen("Pass")}\n{self.cyan(address)}\n{self.yellow("Expected:")} {expected_result},\n{self.yellow("Actual:")} {result}\n'
                self.pass_count += 1
            except AssertionError:
                self.results[test_id] = f'{self.boldRed("Fail")}\n{self.cyan(address)}\n{self.yellow("Expected:")} {expected_result},\n{self.yellow("Actual:")} {result}\n'
                self.fail_count += 1

    def tearDown(self):
        for test_id, result in self.results.items():
            # if 'Fail' in result:
            #     print(f'{self.boldBlue("Test ID:")} {self.cyan(test_id)}, {self.boldBlue("Result:")} {result}')
            print(f'{self.boldBlue("Test ID:")} {self.cyan(test_id)}, {self.boldBlue("Result:")} {result}')
        total_tests = self.pass_count + self.fail_count
        success_rate = round((self.pass_count / total_tests) * 100, 2) if total_tests > 0 else 0
        print(f'Passing tests: {self.pass_count}, Failing tests: {self.fail_count}, Success rate: {success_rate}%')

if __name__ == '__main__':
    unittest.main()
