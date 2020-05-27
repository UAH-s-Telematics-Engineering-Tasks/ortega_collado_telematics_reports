% datos de los últimos 8000 minutos
[d,t,ci] = thingSpeakRead(12397,'NumPoints',8000);

tempF = d(:,4); % campo 4 es temperatura en grados F
humedad = d(:,3); % campo 3 es humedad relativa en porcentaje
DirViento = d(:,1);
VelViento = d(:,2);
tempC = (5/9)*(tempF-32); % conversión a Celsius
camposDisponibles = ci.FieldDescriptions';

% valores máximos, mínimos y media de los datos recogidos
[maxDatos,max_indice] = max(d);
maxDatos = maxDatos';
max_tiempos = datestr(t(max_indice));
max_tiempos = cellstr(max_tiempos);
[minDatos,min_indice] = min(d);
minDatos = minDatos';
min_tiempos = datestr(t(min_indice));
min_tiempos = cellstr(min_tiempos);
mediaDatos = mean(d);
mediaDatos = mediaDatos'; % vector de columnas
resumen = table(camposDisponibles,maxDatos,max_tiempos,mediaDatos,minDatos,min_tiempos); % mostrar

% gráfico circular de la dirección y velocidad del viento durante las últimas 3 horas desde el momento actual
figure(1)
DirViento = DirViento((end-180):end);
VelViento = VelViento((end-180):end);
rad = DirViento*2*pi/360;
u = cos(rad) .* VelViento; % coordinada x velocidad del viento
v = sin(rad) .* VelViento; % coordinada y velocidad del viento
compass(u,v)
titletext = strcat(' durante las últimas 3 horas desde: ',datestr(now));
title({'Velocidad del Viento, MathWorks Weather Station'; titletext})

% cálculos para el punto de condensación
b = 17.62;
c = 243.5;
gamma = log(humedad/100) + b*tempC ./ (c+tempC);
tdp = c*gamma ./ (b-gamma);
tdpf = (tdp*1.8) + 32;  % conversión a Fahrenheit

%grafico humedad, temperatura y punto de condensación de los últimos días desde el momento actual
figure(2)
yyaxis right
plot(t, humedad,'-r');
ylabel('% Humedad')
yyaxis left
plot(t, tempF,'-g');
hold on
plot(t, tdpf,'-b');
ylabel('Grados Fahrenheit')
legend({'Temperatura','Punto de condensación','Humedad'},'Location', 'southwest')
grid on

% datos entre las 0:00 del 4 de junio y las 0:00 del 6 de junio (días 4 y 5 de junio)
[d,t,ci] = thingSpeakRead(12397,'DateRange',[datetime('Jun 4, 2014'),datetime('Jun 6, 2014')]);
presion = d(:,6); % presión
extraDatos = rem(length(presion),60); % puntos excesivos más allá de la hora
presion(1:extraDatos) = []; % eliminamos los puntos excesivos para tener un número par de horas
lluvia = d(:,5); % lluvia registrada por el sensor en pulgadas por minuto

lluvia(1:extraDatos) = [];
t(1:extraDatos) = [];
lluviaHora = sum(reshape(lluvia,60,[]))'; % conversión a muestras sumadas por hora
maxLluviaPorMinuto = max(lluvia);
lluvia5junio = sum(lluviaHora(25:end)); % medimos durante 24 horas desde el 5 de junio
presionHora = downsample(presion,60); % muestras por hora
muestras = downsample(char(t),60); % muestras por hora
muestras = datetime(muestras);

% gráfico lluvia y presión
figure(3)
subplot(2,1,1)
bar(muestras,lluviaHora) % gráfico lluvia
xlabel('Día y Hora')
ylabel('Lluvia (pulgadas /por hora)')
grid on
datetick('x','dd-mmm HH:MM','keeplimits','keepticks')
title('Lluvia el 4 y 5 de junio')
subplot(2,1,2)
hold on
plot(muestras,presionHora) % gráfico presión
xlabel('Día y Hora')
ylabel(camposDisponibles(6))
grid on
datetick('x','dd-mmm HH:MM','keeplimits','keepticks')
tendendia_presion = detrend(presionHora);
presionTendencia = presionHora - tendendia_presion;
plot(muestras,presionTendencia,'r') % gráfico tendencia
hold off
legend({'Presión','Tendencia presión'},'Location','South')
title('Presión el 4 y 5 de junio')

% datos entre las 0:00 del 30 de mayo y las 0:00 del 31 de mayo (día 30 de mayo)
[d,t] = thingSpeakRead(12397,'DateRange',[datetime('May 30, 2014'),datetime('May 31, 2014')]);
datosCrudosTemperatura = d(:,4);
datosNuevosTemperatura = datosCrudosTemperatura;
minTemp = min(datosCrudosTemperatura);

tnew = t';
datosErroneos = [find(datosCrudosTemperatura < 0); find(datosCrudosTemperatura > 120)];
tnew(datosErroneos) = [];
datosNuevosTemperatura(datosErroneos) = [];

% gráfico con y sin datos erróneos
figure(4)
subplot(2,1,2)
plot(tnew,datosNuevosTemperatura,'-o')
datetick
xlabel('Hora del día')
ylabel(camposDisponibles(4))
title('Datos filtrados - datos erróneos eliminados')
grid on
subplot(2,1,1)
plot(t,datosCrudosTemperatura,'-o')
datetick
xlabel('Hora del día')
ylabel(camposDisponibles(4))
title('Datos originales')
grid on

% otra forma de eliminar datos erróneos: comparando un dato con los más próximos a él
n = 5; % número de puntos totales usados en el filtro

f = medfilt1(datosCrudosTemperatura,n);
figure(5)
subplot(2,1,2)
plot(t,f,'-o')
datetick
xlabel('Hora del día')
ylabel(camposDisponibles(4))
title('Datos filtrados - datos erróneos eliminados')
grid on
subplot(2,1,1)
plot(t,datosCrudosTemperatura,'-o')
datetick
xlabel('Hora del día')
ylabel(camposDisponibles(4))
title('Datos originales')
grid on