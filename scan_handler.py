import socket
import requests
import subprocess
import psycopg2
import threading
import re

def parce_request_data(req: str) -> dict:
    req_data = req.split('&')
    if (len(req_data) > 0):
        to_ret = {}
        for param in req_data:
            key, value = param.split('=')
            to_ret[key] = value
        return to_ret
    else : return {}

def add_empty_cols(table, cols_need_count, col_name):
    to_return = []
    for row in table:
        if (len(row) < cols_need_count):
            row.append(col_name)
        to_return.append(row)
    return to_return 

def parse_table(listbuffer, regex_separator) -> list:
    table = []
    for line in listbuffer:
        parsed = re.split(regex_separator, line)
        table.append(parsed)
    return table

def regex_search(listbuffer, regex) -> list:
    confidenses = []
    for line in listbuffer:
        if (re.match(regex, line)):
            confidenses.append(line)
    return confidenses

def regex_replace(listbuffer, regex_to_rm, value_to_rp) -> list:
    to_return = []
    for line in listbuffer:
        line = re.sub(regex_to_rm, value_to_rp, line)
        to_return.append(line)
    return to_return

def run_process(args_list):
    with open('/dev/null', 'w') as null:
        child_proc = subprocess.run(args_list, check=True, stdout=null)

# просканирует цель окроет файлы с отчетами,
# пробежится регуляркой, соберет таблицу, 
# запишет данные в бд

def handle_scan_request(req_data):
    def write_to_db(data_table, scanner_program):
        conn = psycopg2.connect(dbname='gxan', user='postgres',
                                password='admin', host='localhost', port=5433)
        cursor = conn.cursor()

        # line (key: value) кортеж
        # key - column name
        # value - value if it string -> value with ' symbols
        def pg_add_update(table_name, line, conditions):
            keys = '(' 
            vlaues = '('
            for (key, val) in line:
                keys += key + ", " 
                vlaues += val + ", "
            keys = keys[:len(keys)-2] + ")"       # rm , and space 
            vlaues = vlaues[:len(vlaues)-2] + ")"
            req = ''
            res = []
            if (conditions):
                req = f"update {table_name} set {keys} = {vlaues} where {conditions} returning *;"
                cursor.execute(req)
                res = cursor.fetchall()
            if res == []:
                req = f"insert into {table_name}{keys} values {vlaues} returning *;"
                cursor.execute(req)
                res = cursor.fetchall()
            print(req)
            conn.commit()
            return res

        # line: list of columns
        def pg_select(table, line, conditions):
            columns = ''
            for i in line:
                columns += i + " "
            cursor.execute(f"select {columns} from {table} where {conditions};")
            return cursor.fetchall()

        ID_HOST  = ''
        ID_SERVICE = ''
        URL = ''
        IP = req_data['ip']

        # проверяем ессть ли такой хост в списке просканированных
        id_host = pg_select('hosts', ['id_host'], f"ip_addr = '{IP}'")
        if (id_host == []):
            # хост никогда не сканился ранее, добавить его в базу и возьмем id
            res = pg_add_update('hosts', [('ip_addr', f"'{IP}'")], None)
            if (res != None):
                ID_HOST = res[0][0]
        else:
            # когда-то сканился, сохраним его id
            ID_HOST = id_host[0][0]


        if (ID_HOST):
            # есть запись в таблицу hosts для ip адреса
            if (scanner_program == 'nmap'):
                # если только что просканили nmap-ом то, обновить данные в бд для соответствующего хоста
                # или добавить новые записи, если они есть для новых портов
                for line in data_table:
                    upd = pg_add_update('host_services',  
                                        [('id_host', str(ID_HOST)),
                                         ('port_number', f"'{line[0]}'"),
                                         ('filter', f"'{line[1]}'"),
                                         ('protocol', f"'{line[2]}'"),
                                         ('name', f"'{line[3]}'")], 
                                        f"id_host = {ID_HOST} and port_number = '{line[0]}'")
            else:
                # только что скаинили не nmap-ом, смотрим, есть ли таблица для web сайтов

                # извлекаем id скрвиса для спросканированного сайта, или добавляем в таблицу
                web_service = pg_select('host_services', ['id_service'], f"id_host = {ID_HOST} and port_number ~ '80/' ")
                if (len(web_service) == 0):
                    # нету веб сервисов на 80 порту
                    written = pg_add_update('host_services', 
                                            [('id_host', str(ID_HOST)),
                                             ('port_number', f"'80/tcp'"),
                                             ('filter', "'open'"),
                                             ('protocol', "'http'"),
                                             ('name', "'unknown, use nmap for determ'")], None)
                    ID_SERVICE = written[0][0]
                    # теперь есть
                else:
                    ID_SERVICE = web_service[0][0]

                # извлекаем url для соответствующего сервиса, или добавляем, если нету
                url_site = pg_select('web_services', ['url'], f"id_service = {ID_SERVICE} and url = '{req_data['url']}'")
                if (len(url_site) == 0):
                    url = req_data['url']
                    new_site = pg_add_update('web_services', 
                                             [('url', f"'{url}'"),
                                              ('id_service', str(ID_SERVICE))], None)
                    URL = new_site[0][0]
                else:
                    URL = url_site[0][0]


                if (scanner_program == 'nikto'):
                    # сайт сканили на уязвимсти, пишем их в таблицу или обновляем, если там есть уже
                    for line in data_table:
                        res = pg_add_update('vulns', 
                                            [('url', f"'{URL}'"),
                                             ('cve', f"'{line[0]}'"),
                                             ('text', f"'{line[1]}'"),
                                             ('description', f"'{line[2]}'")],
                                            f"url = '{URL}' and cve = '{line[0]}' and text = '{line[1]}'")
                elif (scanner_program == 'dirb'):
                    for line in data_table:
                        res = pg_add_update('dirs',
                                            [('url', f"'{URL}'"),
                                             ('filename', f"'{line[0]}'"),
                                             ('status_code', f"{line[1]}"),
                                             ('size', f"{line[2]}"),
                                             ('is_directory', f"{line[3]}")],
                                            f"url = '{URL}' and filename = '{line[0]}'")
                elif (scanner_program == 'slowhttptest'):
                    for line in data_table:
                        res = pg_add_update('dos_test',
                                            [('url', f"'{URL}'"),
                                             ('second_passed', f"{line[0]}"),
                                             ('conn_closed', f"{line[1]}"),
                                             ('pending', f"{line[2]}"),
                                             ('connected', f"{line[3]}"),
                                             ('is_sevice_alieve', f"{line[4]}")],
                                            f"url = '{URL}' and second_passed = {line[0]}")
        cursor.close()
        conn.close()

    filename = req_data['sid'] # имя файла будет соответствовать номеру сессии

    def scan_make_table(program_args, filename_out, need_cols, reg_search=None,  reg_replace=None, reg_parse=None, callbac_filter=None):
        # step 1: run scan programm fro disk
        run_process(program_args)
        # step 2: read all report files to buffers as lines 
        with open(filename_out) as f:
            program_report = f.readlines()
        # step 3: with use regular expressions make apropriate tables
        # step 3.1: filter all lines with regex, remove lines what needn't for us
        if reg_search:
            program_report = regex_search(program_report, reg_search)
        # step 3.2: remove all symbols in lines
        if reg_replace:
            for regrem in reg_replace:
                (rm, rp) = regrem
                program_report = regex_replace(program_report, rm, rp)
        # step 3.3: parse tables from linex, use regex separator

        if reg_parse:
            report_table = parse_table(program_report, reg_parse)
            for r in report_table:
                if (len(r) < need_cols):
                    r.append(' ');

            if (callbac_filter):
                report_table = callbac_filter(report_table)

            write_to_db(report_table, program_args[0])


    if req_data['port-scan'] == 'on':
        def filter_nmap(lines):
            ret = []
            for line in lines:
                found = re.search('[A-Z].', line[2])
                if (found):
                    tmp = line[3]
                    line[3] = line[2]
                    line[2] = tmp
                ret.append(line)
            return ret

        thread_nmap_scan = threading.Thread(target=scan_make_table, args=(['nmap',req_data['ip'], '-sV', '-o', 'nmap/'+filename],
                                                                          'nmap/'+filename, 4,  r'[1234567890]+\/[tcp|udp]', 
                                                                          [('\n', '')], r' {2,}|.(?<=tcp )|.(?<=closed )|.(?=[A-Z].)|.(?<=filtered )', filter_nmap))
        thread_nmap_scan.start()
        thread_nmap_scan.join()

    if req_data['hiden-dirs'] == 'on':
        def filter_dirb(list_data_scan):
            ret = []
            for line in list_data_scan:
                if (len(line) == 4):
                    # это файл
                    line[3] = 'false'
                elif (len(line) == 2):
                    line[1] = '200'
                    line.append('4094')
                    line.append('true')
                ret.append(line)
            return ret

        thread_dirb_scan = threading.Thread(target=scan_make_table, args=(['dirb', req_data['url'], '-w' , '-o', 'dirb/'+filename],
                                                                          'dirb/'+filename, 4,  r'---- Entering directory: |\+ ',
                                                                          [(r'---- Entering directory: |\+ | ----|\(CODE:|SIZE:|\)', ''),('\n', '') ],
                                                                          r' |\|', filter_dirb))
        thread_dirb_scan.start()
        thread_dirb_scan.join()


    if req_data['dos-test'] == 'on':
        def filter_dos(lines):
            lines.pop(0)
            for line in lines:
                if (int(line[4]) > 0):
                    line[4] = 'true'
                else: line[4] = 'false'
            return lines

        thread_slowhttptest_scan = threading.Thread(target=scan_make_table, args=(['slowhttptest', '-H', '-c', '10000', '-r', 
                                                                                   '100', '-l',  '60','-i', '1', '-n', '1', '-u' ,
                                                                                   req_data['url'] , '-o' ,'slowhttptest/'+filename], 'slowhttptest/'+filename+'.csv', 5,
                                                                                  None, [('\n', '')],  r',', filter_dos))
        thread_slowhttptest_scan.start()
        thread_slowhttptest_scan.join()

    if req_data['vulns-scan'] == 'on':
        thread_nikto_scan = threading.Thread(target=scan_make_table, args=(['nikto', '-url='+req_data['url'], '-ask=no', '-Format=txt', '-output=nikto/'+filename],
                                                                           'nikto/'+filename, 3, r'.+OSVDB.+', [('\n',' '),('\'', '\"')], r': '))
        thread_nikto_scan.start()
        thread_nikto_scan.join()


def main():
    host = '127.0.0.1'
    port = 800

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                try:
                    data = conn.recv(1024)
                except:
                    continue

                if not data:
                    conn.send(b'none data')
                    continue

                try:
                    req_data = parce_request_data(data.decode('utf-8'))
                except:
                    continue

                if (req_data == 0):
                    conn.send(b'erro data')
                    continue

                try:
                    if (req_data['port-scan'] != 'on'):
                        if (req_data['hiden-dirs'] != 'on'):
                            if (req_data['dos-test'] != 'on'):
                                if (req_data['vulns-scan'] != 'on'):
                                    conn.send(b'not ON flags')
                                    continue
                except:
                    conn.send(b'not on flags')
                    continue
                
                threading.Thread(target=handle_scan_request, args=(req_data,)).start()
                print(f'{addr[0]}:{addr[1]}\t', req_data)
                conn.send(b'scan started')

if __name__ == "__main__":
    main()
