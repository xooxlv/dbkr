<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Gxan</title>
        <link href="//localhost:81/css/hack.css" rel="stylesheet">
    </head>

    <body style="background-color: black;">
        <nav style="background-color: #0f1f0f" class="navbar navbar-default navbar-static-top">
            <div class="container">
                <div class="navbar-header">
                    <h2>Gxan</h2>
                </div>
                <div id="navbar" class="navbar-collapse collapse">
                    <ul class="nav navbar-nav navbar-right">
                        <li class="dropdown">
                            <a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-expanded="false">Сканирования<span class="caret"></span> </a>
                            <ul class="dropdown-menu" role="menu">
                                <li>Для дальнешего использования</li>
                            </ul>
                        </li>
                        <li>
                            <a href="#" >Войти</a>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>



        @if ($table_nmap)
        <div class="container">
            <div class="col-md-12" id="ports">
                <br>
                <h2>Обнаружены сервисы</h2>
                <hr>
                <table class="table table-bordered table-hover ">
                    <thead>
                        <tr>
                            <th>№ порта</th>
                            <th>Состояние</th>
                            <th>Сервис</th>
                            <th>Программа и версия</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ($table_nmap as $line)
                        <tr>
                            @foreach($line as $col)
                            @if($col == null)
                            <th>Unknown</th>
                            @else
                            <th>{{$col}}</th>
                            @endif
                            @endforeach
                        </tr>
                        @endforeach
                    </tbody>
                </table>
                <br>
            </div>
            @endif

            @if ($table_nikto)
            <div class="col-md-12" id="vulns">
                <br>
                <h2>Обнаруженные узявимости</h2>
                <hr>
                <table class="table table-bordered table-hover ">
                    <thead>
                        <tr>
                            <th>Уязвимость</th>
                            <th>Описание</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ($table_nikto as $line)
                        <tr>
                            @foreach($line as $col)
                            @if($col == null)
                            <th>Info</th>
                            @else
                            <th style="word-break: break-word;">{{$col}}</th>
                            @endif
                            @endforeach
                        </tr>
                        @endforeach
                    </tbody>
                </table>
                <br>
            </div>
            @endif

            @if ($table_dostest)
            <div class="col-md-12" id="dos-test">
                <br>
                <h2>Результаты dos-тестирования</h2>
                <hr>
                <table class="table table-bordered table-hover ">
                    <thead>
                        <tr>
                            <th>Секунды</th>
                            <th>Закрыто соединений</th>
                            <th>Ожидают подключения</th>
                            <th>Установлено соединений</th>
                            <th>Доступность сервиса</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ($table_dostest as $line)
                        <tr>
                            @foreach($line as $col)
                            @if($col == 't')
                            <th>Доступен</th>
                            @elseif ($col == 'f')
                            <th class="text-danger">Не доступен</th>
                            @else
                            <th>{{$col}}</th>
                            @endif
                            @endforeach
                        </tr>
                        @endforeach

                    </tbody>
                </table>
                <br>
            </div>
            @endif

            @if ($dirs_table)
            <div class="col-md-12" id="files-dirs">
                <br>
                <h2>Обнаруженные файлы и директории</h2>
                <hr>
                <table class="table table-bordered table-hover ">
                    <thead>
                        <tr>
                            <th>URI</th>
                            <th>Размер</th>
                            <th>Статус код</th>
                            <th>Файл\директории</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ($dirs_table as $line)
                        <tr>
                            <th><a href={{$line[0]}}>{{$line[0]}}</a></th>
                            <th>{{$line[1]}}</th>
                            <th>{{$line[2]}}</th>
                            @if ($line[3] === 'f')
                            <th>Файл</th>
                            @endif
                            @if ($line[3] === 't')
                            <th>Директория</th>
                            @endif
                        </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
            @endif
        </div>
    </body>

</html>

