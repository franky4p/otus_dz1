#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr $remote_user $http_x_real_ip [$time_local]
# "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for"
#                     "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';
import os
import re
import logging
import gzip
import itertools
import argparse
import json
from datetime import datetime, date
from collections import Counter, defaultdict
from string import Template

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "NAME_LOG": "myOtus.log",
    "ERROR_PERCENT": 10,
    "NAME_PATERN": 
    "nginx-access-ui.log-[0-9]{4}(0[1-9]|1[012])(0[1-9]|1[0-9]|2[0-9]|3[01])(\.gz)"
}

def main(config):

    logging.info("Program started")

    config.update(parse_config())

    rex = re.compile(config.get("NAME_PATERN"))

    last_date, dir_entry_log = searchfiles(config.get("LOG_DIR"), rex)

    if dir_entry_log is None:
        logging.info("No logs to analyze")
        return

    log_lines = gen_cat(dir_entry_log)

    tuples, error_percent = grep(log_lines)

    if error_percent > config.get("ERROR_PERCENT"):
        logging.error("Error threshold exceeded")
        return

    log = zip_tuples(tuples)

    report_table = most_common_value(log, 'request', 'request_time', 
    config.get("REPORT_SIZE"))
    
    successfully = generate_report(report_table, last_date, 
    config.get("REPORT_DIR"))

    if successfully:
        logging.info("Report generation {} completed".format(last_date))
    else:
        logging.info("Could not generate report {} ".format(last_date))


def zip_tuples(tuples):
    colnames = ('remote_addr', 'remote_user', 'http_x_real_ip', 'time_local', 
    'request', 'status', 'body_bytes_sent', 'http_referer', 'http_user_agent',
    'http_x_forwarded_for', 'http_X_REQUEST_ID', 'http_X_RB_USER',
    'request_time')

    log = (dict(zip(colnames,t)) for t in tuples) 

    return log   

def grep(log_lines):
    """Разбирает строки по заданному формату и возвращает кортеж
    разобранных значений и % ошибок 
    """
    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) (\S+)  (\S+) \[(.+)\] \"(.+)\" ' 
    r'(\d+) (\d+) \"(\S+)\" \"(.+)\" \"(\S+)\" \"(\S+)\" \"(\S+)\" (\S+)')

    match_obj = (pattern.match(line) for line in log_lines)

    #финт ушами, создаем 2 генератора из одного,
    # чтобы проверить количество строк с нарушением формата
    tuple_gen = itertools.tee(match_obj)

    error_percent = percent_error(tuple_gen[0])
    
    tuples = (group.groups() for group in tuple_gen[1] if group)

    return tuples, error_percent


def percent_error(generator_log):
    """Считает полное количество строк и количество строк, не 
    подощедших под формат и возвращает % несоответствия  
    """
    
    all_str = 0
    error_str = 0

    for _ in generator_log:
        all_str += 1
        if _ is None:
            error_str += 1
    
    if all_str > 0:
        error_percent = error_str / all_str * 100
    else:
        error_percent = 0

    return error_percent


def generate_report(report_table, last_date, report_dir):
    """Читает шаблон отчета и если не создан отчет за  last_date
    в директории report_dir создает отчет и заполняет его из report_table 
    """
    name_report = os.path.join(report_dir, "report-{}.html".format(last_date))

    #проверка на уже сформированный отчет
    if os.path.exists(name_report):
        logging.info("Report {} already formed".format(last_date))
        return False

    with open("report.html", "rt", encoding="utf-8") as report:
        templ = report.read()

    if templ:
        s = Template(templ)
        report_tmlt = s.safe_substitute(table_json=str(report_table))

        with open(name_report, "wt") as new_report:
            new_report.write(report_tmlt)
    else:
        logging.exception("Failed to get report template")
        return False

    return True

        
def most_common_value(log, srch_key, sum_key, most_com):
    """По полю поиска srch_key вычисляется сумма по полю sum_key
    и выбирается количество most_com встречаюшихся записей.
    Так же считается количество записей по srch_key, максимальное 
    время, среднее время и медиана. Создается таблица для отчета.
    """
    all_count_time = Counter()
    count_request = Counter()
    max_time_count = Counter()

    sum_request = 0
    sum_request_time = 0
    mediana_dict = defaultdict(list)

    for line in log:
        request_time = float(line[sum_key])

        sum_request += 1
        sum_request_time += request_time

        count_request[line[srch_key]] += 1
        
        all_count_time[line[srch_key]] += request_time
       
        if max_time_count[line[srch_key]] < request_time:
            max_time_count[line[srch_key]] = request_time

        #здесь теряется почти все приемущества генератора
        #т.к.  собираются все значения request_time из файла в список
        #и это печально
        mediana_dict[line[srch_key]].append(request_time)
            
    most_common = all_count_time.most_common(most_com)   
    
    report_table = []

    for el in most_common:
        count_req = count_request.get(el[0])
        max_time = max_time_count.get(el[0])
        time_perc = el[1] / sum_request_time * 100
        count_perc = count_req / sum_request * 100
        time_avg = el[1] / count_req

        sort_list = sorted(mediana_dict.get(el[0]))
        if len(sort_list) % 2 == 0:
            index_med = int(len(sort_list) / 2)
            #середина между центральными значениями
            time_med = (sort_list[index_med] + sort_list[index_med - 1]) / 2
        else: 
            #целая часть от деления будет серединой
            index_med = len(sort_list) // 2   
            time_med = sort_list[index_med]

        log_line = {"count": count_req, "time_avg": time_avg,
                    "time_max": max_time, "time_sum": el[1],
                    "url": el[0], "time_med": time_med,
                    "time_perc": time_perc, "count_perc": count_perc}

        report_table.append(log_line)
   
    return report_table
    

def searchfiles(folder, rex):
    """По заданному формату rex в папке folder ищет самый
    последний исходя из названия файл plate или .gz 
    """
    date_now = datetime.now().date()

    last_file = None
    last_date = date(1980,1,1)

    files = scan_files(folder, rex)

    for element in files:
        list_date_file = re.findall(r"\d{4}\d{2}\d{2}", element.name)
        date_file = datetime.strptime(list_date_file[0], "%Y%m%d").date()

        #если есть сегодняшний лог, берем его,
        #иначе ищем самый последний
        if date_file == date_now:
            last_file = element
            last_date = date_file
            break
        elif date_file >= last_date:
            last_file = element
            last_date = date_file

    return last_date, last_file


def scan_files(folder, rex):

    try:
       sc = os.scandir(folder) 
    except FileNotFoundError:
        logging.exception("Failed to select log for analysis.")    
    else:
        for element in sc:
            need_file = rex.search(element.name)

            if element.is_file() and need_file:
                yield element

        sc.close()
    

def gen_cat(logfile):
    """Открывает файл и считывает из него строки 
    """
    log_opener = gzip.open if logfile.name.endswith(".gz") else open
    log = log_opener(logfile.path, "rt", encoding = "utf-8")

    for line in log:
        yield line    

    log.close()                   
          

def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=argparse.FileType(mode='rt', 
     encoding='utf-8'), default='Config.json')
 
    return parser


def parse_config():
    parser = create_parser()
    #в теории это должно работать, но не моей машине
    #т.ч.  всегда берется default='Config.json'
    args = parser.parse_args()
    
    text = args.config.read()
    
    file_conf = {}

    try:
        file_conf = json.loads(text)
    except:
        logging.exception("Failed to parse config.") 

    args.config.close()

    return file_conf


if __name__ == "__main__":

    logging.basicConfig(filename=config.get("NAME_LOG"), level=logging.INFO,
      format="%(asctime)s %(levelname).1s %(message)s",
      datefmt="%Y.%m.%d %H:%M:%S")

    try:
        main(config)
    except:
        logging.exception("Unhandled exception")