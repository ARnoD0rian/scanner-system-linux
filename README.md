# Scanner system linux

## Рекомендации для пользователя

Для запуска программы необходимо наличие устройства с установленной операционной системой Linux, а также среды разработки, поддерживающей запуск python версии 3.10.7.
Необходимо установить python библиотеки: tkinter, pandas, socket, requests. Для этого необходимо открыть терминал и прописать следующие команды: pip install pandas, pip install tkinker, pip install requests, pip install socket

Для запуска программы необходимо прописать пограмму sudo python3 main.py. После этого откроется меню программы.
В полях начальный и конечный ip указывается диапазон ip адресов. 
Далее необходимо нажать на кнопку диапазон в меню пограммы. Если вы хотите указать не диапазон портов, а файл с портами. То нажмите на кнопку файл с адресами и укажите директорию файла

В полях начальный и конечный port указывается диапазон портов сканирования. После этого необходимо нажать кнопку сохранить порты.
После этого необходимо нажать накнопку «запуск сканера». После этого в таблице появятся открытые порты и их параметры.

Если вы хотите отфильтровать результаты по определнному значению в определенном атрибуте. То нажмите на кнопку «отфильтровать по ппараметрам» и следуйте инструкциям программы. Если вы хотите удалить параметры фильтрации, нажмите на кнопку «очистить фильтры». Для сохранения таблицы необходимо нажать на кнопку «сохранить» и прописать директорию сохранения файла.

