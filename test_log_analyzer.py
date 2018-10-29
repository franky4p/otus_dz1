import log_analyzer
import unittest
import re
from datetime import datetime, date


class LogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up for class"""
        print("setUpClass")

        print("==========")

    def test_searchfiles(self):
        #тест ради теста
        rex = re.compile("кракозябра")
        test_date = date(1980,1,1)
        self.assertTupleEqual(log_analyzer.searchfiles("./log", rex), (test_date, None))

    def test_generate_report(self):
        report_table = [1,2]
        last_date = date(1980,1,1)
        report_dir = "./reports"
        self.assertTrue(log_analyzer.generate_report(report_table, last_date, report_dir))
        #создание 2го должно вернуть False 
        self.assertFalse(log_analyzer.generate_report(report_table, last_date, report_dir))

    def test_percent_error(self):
        generator_log = [1, None, 2, 3]
        self.assertEqual(log_analyzer.percent_error(generator_log), 25)

if __name__ == '__main__':
    unittest.main()