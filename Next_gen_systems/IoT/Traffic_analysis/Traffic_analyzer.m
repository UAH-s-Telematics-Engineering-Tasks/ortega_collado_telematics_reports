% OJO:
    % En Matlab las cadenas encerradas entre comillas simles ('') son en el fondo matrices
    % de caracteres de 1 fila y tantas columnas como caracteres. Son las cadenas "tradicionales"

    % Las cadenas definidas con comillas dobles ("") son en el fondo matrices de cadenas con 1 fila
    % y 1 columna, es decir, 1 elemento. Son como "contenedores" de vectores de caracters.

    % En la gran mayoría de los casos son intercambiables pero en otros no... Para seguir el estilo de
    % C hemos empleado comillas dobles siempre que hemos podido.


% ID del canal de ThingSpeak del que vamos a recoger los datos

CHANNEL_ID = 38629;

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Recogiendo datos desde ThingSpeak %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Recogemos los datos y las marcas de tiempo de los mismos
% No hace falta incluir [channelInfo] ya que no la vamos a usar

[data, timestamps] = thingSpeakRead(CHANNEL_ID);

% Definimos el día de comienzo y fin de la recogida de datos. Con solo
% cambiarlos podemos variar las muestras recogidas. Tened en cuenta que
% tal y como se ha programado la lógica que interpreta las fechas no
% soportamos que el rango incluya años diferentes todavía...

START_DAY = "03-28-2020";
END_DAY  = "04-3-2020";

% Genera dos matrices, start_day y end_day, que contienen las fechas de arriba
% en formato ISO que es el que debemos usar para consultar con bases de datos
% de ThingSpeak

start_day = datetime(START_DAY, "InputFormat", "MM-dd-yyyy");
end_day = datetime(END_DAY, "InputFormat", "MM-dd-yyyy");

% Genera un vector que contenga todas las fechas entre START y END_DAY, ambas inclusive
% Matlab trata todo como matrices. Si bien solemos estar acostumbrados a emplear el término
% array, un array de n elementos no es más que una matriz de una fila y n columnas.

day_vector = start_day:end_day;

% Comprobamos que el último elemento del vector day_vector es en efecto end_day. Si no es así
% (el operador != de C es ~= en Matlab) simplemente lo añadimos al final. Si tenemos un vector A y ejecutamos
% A = [A, B]; estamos concatenando los vectores A y B. Más tarde volveremos a usar este operador...

if (day_vector(end) ~= end_day)
 day_vector = [day_vector, end_day];
end

% Creamos dos matrices vacías para rellenarlas  continuación

traffic_data = [];
time_data = [];

% Como vamos a emplear el número de días varias veces vamos a guardarlo en una variable para poder reutilizarlo

num_days = length(day_vector) - 1;

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Construyendo la primera matriz de datos %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% En Matlab los índices comienzan en 1, no 0... Este bucle for comienza con la variable dia valiendo 1
% y se ejecutará length(day_vector) - 1 veces. El valor de dia se incrementará en 1 en cada iteración.
% En el fondo 1:num_days genera una matriz de 1 fila y num_days elementos
% en el que cada elemento es el anterior incrmentado en 1. Así, el bucle for se ejecuta 1 vez por cada
% elemento y dia tendrá el valor de ese elemento. Nosotros haremos un uso muy sencillo de estos bucles
%
% El equivalente en C sería: for (int i = 0; i < N; i++) donde N = num_days
% La función lenght() devuelve el número de elementos de su argumento, en este caso será el número de
% elementos de day_vector. ¡Tan solo tenemos que restar 1 para ajustar el número de iteraciones y no tener
% 1 de más! Fíjate en que tenemos que leer un elemento y el siguiente, de ahí la necesidad de este pequeño
% ajuste

for dia = 1:num_days
    % El vector day_range tendrá dos fechas consecutivas
    day_range = [day_vector(dia), day_vector(dia + 1)];

    % Pedimos los datos para ese intervalo
    [channel_data, time_marks] = thingSpeakRead(CHANNEL_ID, "DateRange", day_range);

    % Concatenamos traffic_data y channel_data para guardar el reusltado de nuevo en traffic_data
    % Al contrario que antes los vectores se concatenan de manera vertical, no horizontal. Así, si
    % concatenamos dos matrices de 1 fila y 2 columnas horizontalmente el resultado es una matriz
    % de 1 fila y 4 columnas mientras que si lo hacemos verticalmente obtenemos una matriz de 2 filas
    % y 2 columnas. En ese caso queremos organizar los datos de manera que tengamos 2 columnas, una
    % para la zona este y otra para la oeste. Con cada lectura que hagamos iremos añadiendo medidas
    % aumentando el número de filas y manteniendo el de columnas
    [traffic_data] = [traffic_data; channel_data];

    % Este caso es análogo al anterior. Solo señalamos que el operador de concatenación horizontal es ';'
    % mientras que el de concatenación horizontal era ','
    % Asimismo señalamos que al incluir el elemento asignado (el de la izquierda) entre corchetes Matlab
    % no se "queja" de tener que reasignar memoria para una matriz que cambia de tamaño en cada iteración.
    % No obstante hemos dejado ambas formas de hacer esta asignación para mostrar que son las dos factibles
    time_data = [time_data; time_marks];

    % Limpiamos el contenido de las matrices channel_data y time_marks para comenzar una nueva iteración
    % clear channel_data time_marks
end

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Generando la primera gráfica %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Crea una nueva ventana para la figura con el nombre indicado sin mostrar el prefijo "Figure x:"
figure('Name', 'Traffic Density in a Time Range', 'NumberTitle', 'off');

% Dibuja la gráfica empleando los valores de la matriz time_data en el eje X y los de traffic_data en el Y
plot(time_data, traffic_data)

% Formatea los valores que aparecen en el eje X como fechas
datetick

% Etiqueta para el eje X
xlabel("Day");

% Etiqueta para el eje Y
ylabel("Traffic Density");

% Muestra una cuadrícula por "detrás" de la gráfica
grid on

% Título de la gráfica. Hemos empleado sprintf para introducir automáticamente los días de interés. La primera cadena
% que pasamos es la de formato. Donde aparecen los caracteres '%s' se sustituyen las casdenas que se pasan en los demás
% argumentos. En este caso se introducirán START_DAY y END_DAY. La función es prácticamente análoga a la de C
title(sprintf("Traffic density between %s and %s", START_DAY, END_DAY))

% Leyenda que facilita la interpretación de la gráfica
legend("West zone traffic", "East zone traffic");

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Comenzamos a trabajar de nuevo con los datos %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Con estos índices conseguimos:
    % Guardar la primera columna de la matriz traffic_data en west_traffic
    % Guardar la segunda columna de la matriz traffic_data en east_traffic

west_traffic = traffic_data(:,1);
east_traffic = traffic_data(:,2);

num_values = length(west_traffic);

% Con la función floor() ignoramos el resto. Es equivalente a una división entera
% Vemos que por ejemplo: floor(5 / 2) = 2

ratio = floor(num_values / num_days);

% Almacenamos el resto de la división num_values / num_days en remainder. La llamada a
% mod() es equivalente al operador % en C

remainder = mod(num_values, num_days);

% Un par de corchetes vacíos eliminan la parte de la matriz referenciada
% En definitiva estamos eliminando los valores del principio del las
% matrices para lograr que el número de datos sea divisible por el número
% de días. Eliminaremos remainder datos para que el número de valores sea
% divisible por el de días

if (remainder ~= 0)
 west_traffic(1:remainder) = [];
 east_traffic(1:remainder) = [];
end

% Fijamos el número de filas de west_traffic y east_traffic a ratio
% con lo que tendremos exactamente 1 columna por día. Al no tener todos
% los días el mismo número de medidas medidas exactamente nos hemos visto
% obligados antes a eliminar las medidas que impedían que el número de medidas
% fuese divisible por el de días. De lo contrario no tendríamos una matriz
% regular, esto es, no todas las columnas tendrían el mismo número de filas...
% Si no modificamos nuestras matrices para que cumplan esta condición la función
% reshape() nos devolvería un error...

% El parámetro [] significa que no está definido. Matlab nos obliga a pasar
% todos los argumentos al ser posicionales... Es como pasar NULL en C o
% None en Python

% Como su nombre indica, la función mean() nos devuelve el valor medio de los elementos
% de las matrices que le pasamos como argumento. En este caso es la matriz que devuelve
% reshape(). Démonos cuenta de que como a mean() le pasamos una matriz con tantas columnas
% como días nos devuelve una matriz de 1 fila y las mismas columnas con la media de cada una.
% Lo que obtenemos en definitiva es la media de cada uno de los días

west_mean = mean(reshape(west_traffic, ratio, []));
east_mean = mean(reshape(east_traffic, ratio, []));

% Vamos a necesitar el año en el que obtuvimos los datos para
% dibujar la siguiente gráfica. También los emplearemos más adelante

% Para obtener estos datos empleamos la función sscanf() que es parecida a la de C
% En la cadena de la derecha le decimos el formato que esperamos de la cadena que pasamos
% en la izquierda. En este caso esperamos 3 datos enteros separados por guiones
% La función nos devolverá una matriz de 3 filas y 1 columna donde cada fila tendrá uno de los
% enteros leidos. Dado el formato de las fechas la primera fila será el més, la segunda el día
% y la tercera el año

limit_days_data = sscanf(START_DAY, "%d-%d-%d");

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Generando la segunda figura %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

figure('Name', 'Average Density per Day per Zone', 'NumberTitle', 'off');

% Dividimos la figura anterior en 1 fila y 2 columnas.
% Las barras que añadamos ahora se incluirán en la posición
% 1, es decir, la gráfica que dibujamos en la primera columna

subplot(1, 2, 1);

for i = 1:num_days
    % Si la media de este día es menor que 20
    if (west_mean(i) < 20)

        % Genera una barra de color verde en la posición day_vector(i)
        bar(day_vector(i), west_mean(i), "facecolor", "g");

        % Evita que la siguiente barra que dibujemos elimine esta
        hold on;

    % Si la media de este días es mayor que 25
    elseif (west_mean(i) > 25)

        % Dibuja la barra de color rojo
        bar(day_vector(i), west_mean(i), "facecolor", "r");
        hold on;

    % En caso contrario
    else

        % Dibuja la barra de color amarillo
        bar(day_vector(i), west_mean(i), "facecolor", "y");
        hold on;
    end
end

% Formatea el eje X como fechas
datetick

% Etiqueta del eje X
xlabel("Day")

% Etiqueta del eje Y
ylabel("Average traffic density per day")

% Habilita la cudrícula al igual que antes
grid on

% Título de la gráfica. Empleamos de nuevo sprintf() para introducir el año
title(sprintf("Average traffic density per day in the West zone - %d", limit_days_data(3)))

% Ahora dibujaremos en la segunda columna en la que habíamos dividido la figura
% El resto es análogo al caso anterior

subplot(1, 2, 2);
for i = 1:num_days
    if (east_mean(i) < 20)
        bar(day_vector(i), east_mean(i), "facecolor", "g");
        hold on;
    elseif (east_mean(i) > 25)
        bar(day_vector(i), east_mean(i), "facecolor", "r");
        hold on;
    else
        bar(day_vector(i), east_mean(i), "facecolor", "y");
        hold on;
    end
end

datetick
xlabel("Day")
ylabel("Average traffic density per day")
grid on
title(sprintf("Average traffic density per day in the East zone - %d", limit_days_data(3)))

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Comenzamos a trabajar de nuevo con los datos %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% Definimos las matrices de celdas strat_time y stop time. Éstas contendrán celdas que
% a su vez pueden contener cualquier tipo de datos. Si accedemos a estos elementos con
% llaves ({}) obtendremos el valor de la celda deseada pero si empleamos paréntesis (())
% tendremos un subconjunto del contenedor principal que a su vez contiene celdas.
% Nosotros queremos el primer comportamiento!

% En nuestro intervalo de tiempo (2018) el 31 de marzo y el 1 de abril fueron fin de semana
% Este dato cobra importancia al interpretar los datos

% En este bucle generaremos de manera dinámica las cadenas que emplear para hacer las consultas
% a la base de datos de ThingSpeak

for i = 1:num_days
    % Este "interruptor" nos permitirá lidiar con los últimos días de cada més
    flag = false;

    % Como referenciaremos varias veces estos valores los almacenamos en variables temporales
    curr_day = limit_days_data(2);
    curr_month = limit_days_data(1);
    curr_year = limit_days_data(3);

    % Para tener siempre el mismo formato tenemos que rellenar los años, meses y días con
    % ceros por la izquierda para que siempre ocupen 4, 2 y 2 caracteres respectivamente
    % Es por ello que en sprintf() empleamos los especificadores de formato %04d y %02d
    % respectivamente

    % Aquí introducimos un nuevo elemento en cada matriz. Al introducir el primer elemento la matriz
    % se creará automáticamente

    start_time{i} = sprintf('%04d-%02d-%02d 00:00:00.000', curr_year, curr_month, curr_day);
    stop_time{i}  = sprintf('%04d-%02d-%02d 23:59:59.999', curr_year, curr_month, curr_day);

    % Comprobamos si tenemos algún caso especial. No tenemos en cuenta años bisisestos y que creemos que
    % complica el código sin aportar demasiado... Si se da cualquier condición acabaremos por ejecutar
    % la cláusula if de la condición final. En caso contrario ejecutaremos la cláusula else

    % Los operadores lógicos son los mismos que en C:
        % && --> AND
        % || --> OR
        % == --> EQUAL

    if (curr_day == 30 && (curr_month == 4 || curr_month == 6 || curr_month == 9 || curr_month == 11))
        flag = true;

    elseif(curr_day == 28 && curr_month == 2)
        flag = true;

    elseif (curr_day == 31)
        flag = true;
    end

    if (flag)
        limit_days_data(2) = 1;

        % Matlab no permite incrementar con los operadores ++ o +=...
        limit_days_data(1) = limit_days_data(1) + 1;
    else
        limit_days_data(2) = limit_days_data(2) + 1;
    end
end

% Con los datos preparados pasamos a hacer peticiones a la base de datos y
% constrir gráficas para cada uno de los días

for i = 1:num_days
    % Obtenemos los tiempos inicial y final de cada día en formato ISO
    % para poder hacer la consulta a la base de datos externa de ThingSpeak

    t_o = datetime(start_time{i}, 'InputFormat', 'yyyy-MM-dd HH:mm:ss.SSS');
    t_f = datetime(stop_time{i}, 'InputFormat', 'yyyy-MM-dd HH:mm:ss.SSS');

    % Concatenamos esos tiempos para formar una matriz de 1 fila y 2 columans
    day_vector = [t_o, t_f];

    % Desempaquetamos los datos que llegan desde ThingSpeak y que pedimos empleando
    % la matriz que generábamos antes

    [day_data, time_data] = thingSpeakRead(CHANNEL_ID, 'DateRange', day_vector);

    % Almacenamos en west_day_data, una matriz de 1 columan y tantas filas como datos lleguen,
    % la primera columna de day_data

    west_day_data = day_data(:,1);

    % Hacemos lo propio guardando la segunda columna en east_day_data
    east_day_data = day_data(:,2);

    % Obtenemos la cadena que representa el día actual de la forma 'yyyy-MM-dd HH:mm:ss.SSS'
    data_day = start_time{i};

    % Nos quedamos con la fecha obviando la hora para luego mostrarla en la gráfica que generamos
    data_day = {data_day(1:length('yyyy-MM-dd'))};

    % Mostramos los datos en intervalos mayores de los que nos llegan
    % directamente de la base de datos para que todo se vea de manera más clara
    % Emplearemos intervalos de 30 minutos; día tiene 48 periodos de 30 min

    half_hours_per_day = 24 * 2;

    % Vemos cuantos datos le corresponden a cada intervalo de 30 minutos redondeándolo a la baja
    num_half_hours = floor(length(west_day_data) / half_hours_per_day);

    % Reducimos la tasa de muestreo de la señal. Con los días que tiene ahora configurado el programa
    % time_data tiene 5667 filas con lo que num_half_hours = 118. Bajar la tasa de sampleo, es decir,
    % el número de muestras se corresponde formalmente con obtener la señal x'[n] = x[n·K] a partir de
    % la señal x[n]. Así, de cada K muestras de x[n] (time_data para nosotros) nos quedamos solo con 1
    % muestra y las otras 117 se descartan. Si pensamos en ello, vemos como x'[0] = x[0], x'[1] = x[K],
    % x'[2] = x[2·K]... En nuestro caso K = 118 con lo que las tres primeras muestras de x'[n] son
    % x[0], x[118] y x[236]. En definitiva, las 354 primeras muestras de x[n] se resumen en 3 de x'[n]
    % con lo que las 5667 se resumen en aproximadamente 48 (recordemos que 5667 no es múltiplo de 48).
    % Con todo, lo que estamos haciendo es reducir la tasa de datos de la señal devuelta por un factor
    % de K, siendo K el segundo parámetro que le pasamos a downsample()

    % Tal y como está planteado al final acabaremos con marcas de tiempo que siempre rozan los 30 minutos
    % o la hora en punto, es decir, marcas del tipo XX:29:YY o XX:01:YY que son las que están en los límites
    % de los conjuntos de muestras que eliminamos. Como solo queremos estos tiempos para mostrarlos en la
    % figura correspondiente no "pasa nada" por eliminar tantas muestras. No es lo mismo si estuviéramos
    % hablando de matrices de datos...

    half_hour_instants = downsample(time_data, num_half_hours);

    % Obtenemos la media de los valores pertenecientes a estos intervalos de media hora para cada zona
    % Si pensamos en los valores que irá tomando j:
        % j = 1 --> mean(1:num_half_hours)
        % j = 2 --> mean(1 + num_half_hours:2 * num_half_hours)

    % Vemos que vamos tratando los datos en intervalos de media hora tal y como esperábamos

    for j = 1:half_hours_per_day
        west_data_half_hour(j) = mean(west_day_data(1 + num_half_hours * (j - 1):num_half_hours * j));
        east_data_half_hour(j) = mean(east_day_data(1 + num_half_hours * (j - 1):num_half_hours * j));
    end
    
    % Borramos el primer elemento de los instantes que habíamos recortado antes
    % con lo que el primer tiempo es aproximadamente 00:30 en vez de 00:00 que
    % es donde empiezan todos los tiempos (recuerda que start_time siempre
    % comienza en el instante 00:00:00.000)

    half_hour_instants(1) = [];

    % Convertimos nuestro formato de fechas a representaciones de fecha según la ISO para poder
    % añadirlas de manera cómoda a la gráfica

    half_hour_instants_conv = datetime(half_hour_instants, 'InputFormat', 'yyyy-MM-dd HH:mm:ss.SSS');

    % Generamos una gráfica para cada día. Como el procedimiento es análogo a las figuras anteriores
    % solo señalamos los aspectos nuevos

    figure('Name', sprintf("Traffic intensity on %s", data_day{1}), 'NumberTitle', 'off');
    subplot(1, 2, 1);

    % Mostramos los máximos locales al no especificar variables que recojan el resultado devuelto
    % Mostraremos solo aquellos máximos que tengan al menos una diferencia de 0.3 con sus vecinos
    % y que tengan una altura mínima de 5

    findpeaks(west_data_half_hour, half_hour_instants_conv, 'Threshold', 0.3, 'MinPeakHeight', 5)
    datetick
    xlabel('Time of the day')
    ylabel('Traffic density every 30 minutes')

    % Concatenamos dos matrices de caracteres al igual que se logra en C con strcat() o en Python
    % con una simple "suma" de cadenas con el operador +
    title(['Traffic density in the Western area for day ', data_day])

    subplot(1, 2, 2);
    findpeaks(east_data_half_hour, half_hour_instants_conv, 'Threshold', 0.3, 'MinPeakHeight', 5)
    datetick
    xlabel('Time of the day')
    ylabel('Traffic density every 30 minutes')
    title(['Traffic density in the Eastern area for day ', data_day])
end
