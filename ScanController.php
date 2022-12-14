<?php
namespace App\Http\Controllers;

use Exception;
use Illuminate\Support\Facades\Request;
use Illuminate\Validation\Rules\Enum;

class ScanController extends Controller
{
    // --------------значения и клчи для сесиий----------------- 
    private static $SCAN_ON = 1; //  нужно скнить
    private static $SCAN_OFF = 2; // не нужно

    private static $key_port_scan = 'nmap';
    private static $key_dir_scan = 'dirb';
    private static $key_dos_test = 'slowhttptest';
    private static $key_vuln_scan= 'nikto';
    private static $key_url = 'url';
    // --------------значения и клчи для сесиий----------------- 

    private static function determ_ip($ulr){
        return  gethostbyname($ulr);
    }

    private static function db_select($req){
        $conn = pg_connect("host=localhost port=5433 dbname=gxan user=postgres password=admin");
        $table = [];
        if (!$conn) {
            return redirect('505.html');
        }

        $result = pg_query($conn, $req);
        if (!$result) {
            return redirect('505.html');
        }

        while ($row = pg_fetch_row($result)) {
            array_push($table, $row);
        }
        return $table;
    }

    public function get_results(){
        $vulns_scanning = session()->get(ScanController::$key_vuln_scan);
        $dirs_scanning = session()->get(ScanController::$key_dir_scan);
        $port_scanning = session()->get(ScanController::$key_port_scan);
        $dos_testing = session()->get(ScanController::$key_dos_test);
        $url = session()->get(ScanController::$key_url);

        $table_vulns = null;
        $table_ports = null;
        $table_dirs = null;
        $table_dos = null;

        if ($vulns_scanning == ScanController::$SCAN_ON){
            $req = "select  text, description from vulns where url ~ '" . $url. "'";
            $table_vulns = ScanController::db_select($req);
        }

        if ($dirs_scanning == ScanController::$SCAN_ON){
            $req = "select filename, size, status_code, is_directory from dirs where url ~ '" . $url. "'";
            $table_dirs = ScanController::db_select($req);
        }

        if ($dos_testing == ScanController::$SCAN_ON){
            $req = "select second_passed, conn_closed, pending, connected, is_sevice_alieve from dos_test where url ~ '" . $url. "' order by second_passed";
            $table_dos = ScanController::db_select($req);

            foreach ($table_dos as $line){
                preg_replace('/f/', 'Не доступен', $line);
                preg_replace('/t/', 'Доступен', $line);
            }
        }

        if ($port_scanning == ScanController::$SCAN_ON){
            $req = "select port_number, filter, protocol, name from host_services 
                where id_host in (
                    select id_host from hosts where ip_addr = '" . ScanController::determ_ip($url) . "')";
            $table_ports = ScanController::db_select($req);
        }

        if ( (($table_dirs == null) and ($dirs_scanning == ScanController::$SCAN_ON)) or
            (($table_ports == null) and ($port_scanning == ScanController::$SCAN_ON)) or
            (($table_dos == null) and ($dos_testing == ScanController::$SCAN_ON)) or 
            (($table_vulns == null) and ($vulns_scanning == ScanController::$SCAN_ON))){
            return redirect('loading.html');
        }

            return view('scan', 
                ['table_nmap' => $table_ports,
                'table_nikto' => $table_vulns,
                'table_dostest' => $table_dos,
                'dirs_table' => $table_dirs]);
    }

        public function scan(Request $req){

            // принимает список задач и цель для сканирования
            // в сесиию записываются все сканирования, которые будут проводиться
            // делается запрос на бд, если данные есть то их в шаблонизатор и сессию установить, как данные получены
            // если в бд пусту, в сесии записать к каждому скану статус - сканируется
            // запустить скан, дождаться ответа о начале сканаа
            // вернуть ответ в браузер

            // --------------для работы днс----------------- 
            $url_to_scan = null; // like yandex.ru
            $full_url = null;   // line https://yandex.ru/
            $ip_to_scan = null;
            // --------------для работы днс----------------- 

            // --------------клиентские данные ----------------- 
            $data = Request::all();
            $keys = array_keys($data);

            $port_scan = null;
            $hiden_dirs = null;
            $dos_test = null;
            $vulns_scan = null;
            // --------------клиентские данные ----------------- 

            // установить флаги отвечабщие за сканирования в переменных как on 
            // для всех запрашиваемых клиентом типов скана устан в сесии метку В ПРОЦЕССЕ
            session()->flush();
            foreach ($keys as $key){
                if ($key === 'url'){
                    $full_url = $data[$key];
                    $url_to_scan = preg_replace('/(https?:\/\/)|(\/)/', '', $full_url);
                    $ip_to_scan = ScanController::determ_ip($url_to_scan);
                }
                elseif ($key === 'port-scan'){
                    $port_scan = 'on';
                    session()->put(ScanController::$key_port_scan, ScanController::$SCAN_ON);
                }
                elseif ($key === 'vulns-scan'){
                    $vulns_scan = 'on';
                    session()->put(ScanController::$key_vuln_scan, ScanController::$SCAN_ON);
                }
                elseif ($key === 'hiden-dirs'){
                    $hiden_dirs = 'on';
                    session()->put(ScanController::$key_dir_scan, ScanController::$SCAN_ON);
                }

                elseif ($key === 'dos-test'){
                    $dos_test = 'on';
                    session()->put(ScanController::$key_dos_test, ScanController::$SCAN_ON);
                }
            }
            // неустановленные сесии зополнить занчениями СКАН НЕ ТРЕБУУЕТСЯ
            session()->get(ScanController::$key_port_scan)? null: session()->put(ScanController::$key_port_scan, ScanController::$SCAN_OFF);
            session()->get(ScanController::$key_dir_scan)? null: session()->put(ScanController::$key_dir_scan, ScanController::$SCAN_OFF);
            session()->get(ScanController::$key_dos_test)? null: session()->put(ScanController::$key_dos_test, ScanController::$SCAN_OFF);
            session()->get(ScanController::$key_vuln_scan)? null: session()->put(ScanController::$key_vuln_scan, ScanController::$SCAN_OFF);
            session()->put(ScanController::$key_url, $url_to_scan);

            // зополнить отключенные флаги значением off
            $port_scan = ($port_scan === 'on' ) ? 'on' : 'off';
            $vulns_scan = ($vulns_scan === 'on' ) ? 'on' : 'off';
            $hiden_dirs = ($hiden_dirs === 'on' ) ? 'on' : 'off';
            $dos_test = ($dos_test === 'on' ) ? 'on' : 'off';
            $sid = session()->getId();

            // сделать запрос с python сервису с просьбой начать сканирование адреса способами, помеенными как on
            $reqparams = "sid=${sid}&url=${full_url}&ip=${ip_to_scan}&port-scan=${port_scan}&hiden-dirs=${hiden_dirs}&dos-test=${dos_test}&vulns-scan=${vulns_scan}";
            $sock = socket_create(AF_INET, SOCK_STREAM, STREAM_IPPROTO_TCP);
            try{
                socket_connect($sock, '127.0.0.1', 800);
                socket_send($sock, $reqparams, strlen($reqparams), 0);
                $res = null;
                socket_recv($sock, $res, 1500, 0);
                if ($res === 'scan started'){
                    return redirect('loading.html');
                }
                else {
                    return redirect('505.html');
                }
            }
            catch (Exception $ex){
                return redirect('505.html');
            }

        }
    }
