<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <title>Gxan</title>
        <link href="css/hack.css" rel="stylesheet">

        <style>
        .tall-row {
            margin-top: 40px;
        }
        .modal {
            position: relative;
            top: auto;
            right: auto;
            left: auto;
            bottom: auto;
            z-index: 1;
            display: block;
        }
        </style>
    </head>

    <body style="background-color: black">
        <nav style="background-color: #0f1f0f" class="navbar navbar-default navbar-static-top">
            <div class="container">
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


        <div class="container">
            <div class="container">
                <!-- Jumbotron -->
                <div class="jumbotron">
                    <h1 style="  text-shadow: 0 -40px 100px, 0 0 2px, 0 0 1em lime">Gxan</h1>
                    <p>Сканер уязвимостей информационной безопасности на сайтах обнаружит самые популярные ошибки на вашем сайте, эксплуатируемые злоумышленниками.</p>
                    <p>Проведет автоматическое сканирование сайта по выбранным категориям сканирования.</p>
                    <p>
                    <a class="btn btn-lg btn-primary" role="button">Подробнее »</a>
                    </p>
                </div>

                <!-- Typography -->
                <div class="row tall-row">
                    <div class="col-lg-12">
                        <h1>Как мы работаем</h1>
                        <em>Сервис предоставляет доступ вам просканировать ваш сайт программами, используемыми злоумышленниками и сетевыми
                            ботами для автоматического сканирования сайтов в сети интернет и поиска уязвимостей информационной безопасности на них. Наш сервис не нанесет
                            вреда Вашим сайтам при сканировании. Для сканирования используются: сетевой сканер портов <a class="text-danger" href="#">nmap</a>,
                            сканер уязвимостей <a class="text-danger" href="#">nikto</a>,сканер скрытых файлов и директорий <a class="text-danger" href="#">dirb</a>,
                            программа для стресс-тестирования <a class="text-danger" href="#">slowhttptest</a> </em>
                        <hr>
                    </div>
                </div>

                <div class="row tall-row">
                    <div class="col-lg-12">
                        <h1>Сканирование</h1>
                        <hr>
                    </div>
                </div>

                <div class="row">
                    <div class="col-lg-6">
                        <div class="well">
                            <form class="form-horizontal" method="post" action="/scan">
                                @csrf
                                <fieldset>
                                    <legend>Данные Вашего сайта</legend>
                                    <div class="form-group">
                                        <label class="control-label" for="focusedInput">URL сайта</label>
                                        <input class="form-control" name="url" id="focusedInput" value="http://" type="text">
                                    </div>
                                    <div class="checkbox">
                                        <label> <input name="port-scan" type="checkbox"> Сканирование портов </label><br><br>
                                        <label> <input name="hiden-dirs" type="checkbox"> Поиск скрытых файлов и директорий </label><br><br>
                                        <label> <input name="dos-test" type="checkbox"> DOS - тестирование </label><br><br>
                                        <label> <input name="vulns-scan" type="checkbox"> Сканирование уязвимостей TOP 10 OWASP </label><br><br>
                                    <input class="btn btn-default" type="submit" value="Запуск">
                                </fieldset>
                            </form>
                        </div>
                    </div>
                    <div class="col-lg-6" rows="16" id="term">
                        <p>PING</p>
                        <textarea id="ping" class="form-control" name="textarea" rows="16" cols="30" readonly>
                        </textarea>
                    </div>
                </div>
            </div>
            <div class="row tall-row">
            <div class="col-md-12">
                <p>Styled by Tobin Brown</a>. &copy; 2015</p>
            </div>
        </div>

        </div>

<script>

let elem = document.querySelector('#focusedInput');
let pingfield = document.querySelector('#ping');
elem.addEventListener('input', async function() {
    let data = '┌──(ping㉿anonimous)-[local]\n└─$ ping '
    let addr = this.value
    addr = addr.replace('http://', '').replace('https://', '')
    let pingedaddr = await ping(addr)
    pingfield.innerHTML = data + addr + '\n' +  pingedaddr.join('\n')
});

async function ping(addr) {
    const response = await fetch('/ping/' + addr, {
        method: 'GET',
            headers: {
            'Content-Type': '*/*'
            }
    })
    const data = await response.json()
    return data
}
</script>

</body>
</html>
