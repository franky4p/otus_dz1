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
from datetime import datetime, date
from collections import Counter
from string import Template

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "NAME_PATERN": 
    "nginx-access-ui.log-[0-9]{4}(0[1-9]|1[012])(0[1-9]|1[0-9]|2[0-9]|3[01])"
}


def grep(log_lines):

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
    #больше 60% времени цп жрет эта функция 
    #с этим нужно что-то делать
    
    all_str = 0
    error_str = 0

    for _ in generator_log:
        all_str += 1
        if _ is None:
            error_str += 1
    
    if all_str > 0:
        error_percent = error_str/all_str * 100
    else:
        error_percent = 0

    return error_percent


def main():

    name_log = "myOtus.log"
    
    logging.basicConfig(filename=name_log, level=logging.INFO,
      format="%(asctime)s %(levelname).1s %(message)s",
      datefmt="%Y.%m.%d %H:%M:%S")

    logging.info("Program started")

    folder = config.get("LOG_DIR")
    report_dir = config.get("REPORT_DIR")
    pattern_name = config.get("NAME_PATERN")
    most_com = config.get("REPORT_SIZE")

    rex = re.compile(pattern_name)

    last_date, dir_entry_log = searchfiles(folder, rex)

    if dir_entry_log is None:
        logging.info("Логов нет")
        return

    log_lines = gen_cat(dir_entry_log)

    tuples, error_percent = grep(log_lines)

    if error_percent >= 10:
        logging.error("Превышен порог ошибок")
        return

    colnames = ('remote_addr','remote_user','http_x_real_ip','time_local', 
    'request', 'status','body_bytes_sent','http_referer','http_user_agent',
    'http_x_forwarded_for','http_X_REQUEST_ID','http_X_RB_USER','request_time')

    log = (dict(zip(colnames,t)) for t in tuples)

    report_table = most_common_value(log, 'request', 'request_time', most_com)
    
    successfully = generate_report(report_table, last_date, report_dir)

    if successfully:
        logging.info("Формирование отчета {} завершено".format(last_date))
    else:
        logging.info("Не удалось сформировать отчет {} ".format(last_date))


def generate_report(report_table, last_date, report_dir):
    name_report = os.path.join(report_dir, "report-{}.html".format(last_date))

    if os.path.exists(name_report):
        logging.info("Отчет за {} уже сформирован".format(last_date))
        return False

    with open("report.html", "rt", encoding="utf-8") as report:
        templ = report.read()

    if templ:
        s = Template(templ)
        report_tmlt = s.safe_substitute(table_json=str(report_table))

        with open(name_report, "wt") as new_report:
            new_report.write(report_tmlt)
    else:
        logging.exception("Не удалось получить шаблон отчета")
        return False

    return True

        
def most_common_value(log, srch_key, sum_key, most_com):
    
    all_count_time = Counter()
    count_request = Counter()
    max_time_count = Counter()

    sum_request = 0
    sum_request_time = 0

    for line in log:
        request_time = float(line[sum_key])

        sum_request += 1
        sum_request_time += request_time

        count_request[line[srch_key]] += 1
        
        all_count_time[line[srch_key]] += request_time
       
        if max_time_count[line[srch_key]] < request_time:
            max_time_count[line[srch_key]] = request_time

    most_common = all_count_time.most_common(most_com)   
    
    report_table = []

    for el in most_common:
        count_req = count_request.get(el[0])
        max_time = max_time_count.get(el[0])
        time_perc = el[1]/sum_request_time * 100
        count_perc = count_req/sum_request * 100
        time_avg = el[1]/count_req

        log_line = {"count": count_req, "time_avg": time_avg,
                    "time_max": max_time, "time_sum": el[1],
                    "url": el[0], "time_med": 1,
                    "time_perc": time_perc, "count_perc": count_perc}

        report_table.append(log_line)
   
    return report_table
    

def searchfiles(folder, rex):
    date_now = datetime.now().date()

    last_file = None
    last_date = date(1980,1,1)

    try:
       sc = os.scandir(folder) 
    except FileNotFoundError:
        logging.exception("Не удалось выбрать лог для анализа")    
    else:
        with sc:
            for element in sc:
                if element.is_file():
                    need_file = rex.search(element.name)

                    if need_file:
                        list_date_file = re.findall(r"\d{4}\d{2}\d{2}", element.name)
                        date_file = datetime.strptime(list_date_file[0], "%Y%m%d").date()

                        #не придумал регулярку для фильтра .bz2 и т.п.
                        if (element.name.endswith(list_date_file[0]) or 
                        element.name.endswith(".gz")):
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


def gen_cat(logfile):
    if logfile.name.endswith(".gz"):
        log = gzip.open(logfile.path, "rt", encoding = "utf-8")
    else:
        log = open(logfile.path,"rt", encoding = "utf-8")

    for line in log:
        yield line    

    log.close()                   


def printlines(lines):
    for line in lines:
        print(line)
          

if __name__ == "__main__":
    main()
