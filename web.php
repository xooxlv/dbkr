<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ScanController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function(){
    return view('home');
});

Route::post('/scan', [ScanController::class, 'scan']);

Route::get('/status', [ScanController::class, 'get_results']);
Route::get('/result', [ScanController::class, 'get_results']);


Route::get('/ping/{address}', function (Request $req, $address){
    $output = null; $retcode = -1;
    exec("ping ${address} -c 6 -i 0.02 -n -W 1", $output, $retcode);
    return response($output);
});

