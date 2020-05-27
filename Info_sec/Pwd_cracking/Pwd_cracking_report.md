# Datos técnicos
Tal y como se explica en el guión de la práctica debemos escoger un fichero con *hashes* para analizar así como una herramienta de auditoría y un diccionario del que partir. En nuestro caso hemos optado por analizar los archivos `raw-md5.hashes4.txt` y `raw-md5.hashes5.txt`. Asimismo y tal y como se recomienda hemos trabajado con *hashcat* para intentar recuperar las contraseñas a partir de los *hashes* contenidos en dichos archivos. Finalmente señalamos que hemos empleado dos diccionarios base para nuestras pruebas. En primer lugar hemos empleado el archiconocido `rockyou.txt` así como el diccionario por defecto de la herramienta *John the Ripper* que, en nuestro caso, denominaremos `john.txt`. Este programa es muy similar a *hashcat* y tal y como aparece en {1} es venerado por su gran calidad. Destacamos asimismo que, tal y como comentaremos al analizar los distintos ataques en profundidad, las contraseñas contenidas en estos diccionarios no son las únicas que comprobaremos pues asistiremos a tipos de ataques que nos permiten recombinar el diccionario original para aumentar las candidatas a probar.

# Problemas con la instalación
Antes de empezar a emplear *hashcat* para trabajar nos topamos con un ligero problema. Al invocar el programa para cerciorarnos de que todo funcionaba correctamente con `hashcat --benchmark` vimos cómo el propio *hashcat* nos informaba de no haber encontrado dispositivos compatibles para lleavar a cabo su trabajo. Como nuestra intención era usar simplemente la CPU para calcular los hashes necesarios y la versión instalada se correspondía con este fin nos pareció realmente extraño estar en esta situación. Tomando el error impreso como punto de partida nos dispusimos a encontrar una solución.

Tras navegar durante un rato al final descubrimos que nuestro equipo no tenía el *OpenCL Runtime* instalado para procesadores *Intel Core*. Tal y como se aprecia en {2}, este *framework* nos ofrece una *API* (**A**pplication **P**rogramming **I**nterface) para ejecutar programas en máquinas heterogéneas. Al tener nuestro sistema tan solo una implementación libre en vez de la oficial *hashcat* nos informaba de que la velocidad podía verse muy afectada.

Tras navegar de nuevo por la red encontramos y descargamos el driver de {3}. Para que el proceso de instalación tuviera éxito tuvimos que instalar un par de librarías que, según el instalador, no estaban presentes. Lo pudimos lograr sin problemas con:

```bash
sudo apt update && sudo apt install libtinfo5 lsb-core
```

Adjuntamos asimismo una captura de pantalla del instalador:


Con todo listo simplemente ejecutamos `hashcat -I` para consultar los dispositivos detectados por *hashcat*. El dispositivo que hace uso del driver que acabamos de instalar está asociado al identificador `2` en nuestro caso. Es por ello que una de las opciones que siempre aparecerá en nuestras órdenes es `-d 2` indicando que el dispositivo a emplear es aquel del que podremos obtener un mayor rendimiento.

# Resumen ejecutivo
Si algo hemos sacado en claro tras realizar la práctica es la fragilidad de las contraseñas que como usuarios empleamos día a día. Como curiosidad probamos a atacar nuestras contraseñas generando el hash *MD5* de la misma con la siguiente orden:

```bash
echo 'nuestra_contraseña' | md5sum | awk '{print $1}' > my_pwd_hash.txt
```

Este es entonces el archivo a analizar y, sin sorpresa alguna, la contraseña se descubrió absurdamente rápido. Así, no solamente resulta inquietante lo rápido que se pueden romper las contraseñas sino también lo sencillo que resulta. Hacer lo que hemos hecho nosotros es cuestión de descargar una herramienta de internet, instalarla y simplemente arramplar con lo que se desee. Esta facilidad pasmosa es una de las razones por la que tras acabar la práctica lo primero que hemos hecho ha sido cambiar las contraseñas de varios servicios. Saber que algo tan frágil es la primera línea de defensa ante los atacantes le quitaría el sueño a cualquiera...

Dejando de lado lo anterior también señalamos que hemos aprendido cómo auditar contraseñas de una manera sólida. Creemos que esta habilidad podría ser tremendamente útil de cara a la vida laboral y nos alegramos de haber podido comprender cómo funcionan estos procedimientos que, si nos guiamos por el cine y la televisión, parece estar al alcance de muy pocos.

También hemos interiorizado la diferencia clara que hay entre unos ataques y otros. Comprender este hecho es la clave para poder llevar a cabo estas auditorías en el menor tiempo posible manteniendo la mayor eficacia.

Finalmente señalamos que, motivados por la curiosidad, leímos acerca de métodos más avanzados de auditoría como pueden ser las *Rainbow Tables*. Nos pareció tremendamente interesante observar las estrategias para diseñar una estructura de datos que minimizara estos tiempos de búsqueda de contraseñas.

Con todo pasamos a comentar los aspectos más relevantes de cada tipo de ataque:

## Ataque de diccionario o *straight mode attack*
Este tipo de ataque es quizá el más sencillo pero no por eso inútil.

## Analizando `raw-md5.hashes5.txt`

### Ataque de diccionario
Con este tipo de ataque pretendemos probar todas las contraseñas recogidas en un diccionario o *wordlist* para comprobar si se corresponde con alguno de los *hashes* contenidos en el archivo a analizar. En esta ocasión se probarán las palabras del diccionario "tal cual", no se modificarán de ninguna manera.

Llevar a cabo este tipo de ataque resulta sencillo empleando *hashcat*. Tras consultar el manpage de la herramienta con `man hashcat` vimos cómo el teníamos que especificar una serie de parámetros. Los relacionamos a continuación:

1. Tipo de *hashes* del archivo a analizar. En nuestro caso son *hashes MD5* con lo que el tipo a pasarle a la opción `-m` es `0`.

2. Tipo de ataque a realizar. En nuestro caso es un ataque de diccionario lo que supone de nuevo el tipo `0` pero en esta ocasión para la opción `-a`.

3. Archivo a auditar. En nuestro caso será `raw-md5.hashes5.txt`.

4. Diccionario del que obtener las contraseñas candidatas. Nosotros emplearemos `rockyou.txt`.

Además de los anteriores también hemos optado por especificar que los *hashes* "rotos" se guarden en el archivo `dict_hits.txt`, cosa que logramos con la opción `-o`. Asimisme le impedimos a *hashcat* que almacene los hashes ya descubiertos en un archivo interno (el *potfile*) par que cada ataque sea como "nuevo". Podemos lograr este comportamiento con `--potfile-disable`. Recordamos también que tal y como decíamos al comienzo, adjuntamos la opción `-d` para seleccionar el dispositivo más optimizado.

Nótese que no aprovechamos las contraseñas ya descubiertas para agilizar ataques posteriores porque queremos poder hacer comparaciones fidedignas. Entendemos que los hashes no descubiertos corresponden a las contraseñas más "difíciles" ya que no las hemos encontrado con un ataque determinado. Es por ello que no es "justo" comparar 2 estrategias de ataque cuando una debe enfrentarse a contraseñas aparentemente más complicadas que otras.

Con todo lo anterior el comando y su resultado son:
```bash
$ time hashcat -m 0 -a 0 -d 2 -o dict_hits.txt --potfile-disable raw-md5.hashes5.txt rockyou.txt
hashcat (v5.1.0) starting...

* Device #1: Not a native Intel OpenCL runtime. Expect massive speed loss.
             You can use --force to override, but do not report related errors.
OpenCL Platform #1: The pocl project
====================================
* Device #1: pthread-Intel(R) Core(TM) i7-5500U CPU @ 2.40GHz, skipped.

OpenCL Platform #2: Intel(R) Corporation
========================================
* Device #2: Intel(R) Core(TM) i7-5500U CPU @ 2.40GHz, 3982/15928 MB allocatable, 4MCU

# Parte de la salida omitida por claridad

Session..........: hashcat
Status...........: Exhausted
Hash.Type........: MD5
Hash.Target......: raw-md5.hashes5.txt
Time.Started.....: Sat May  2 14:47:05 2020 (12 secs)
Time.Estimated...: Sat May  2 14:47:17 2020 (0 secs)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:  1202.4 kH/s (0.54ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 156897/3500000 (4.48%) Digests, 0/1 (0.00%) Salts
Recovered/Time...: CUR:N/A,N/A,N/A AVG:787827,47269620,1134470896 (Min,Hour,Day)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#2....: $HEX[206b6d3831303838] -> $HEX[042a0337c2a156616d6f732103]

Started: Sat May  2 14:46:55 2020
Stopped: Sat May  2 14:47:18 2020

real    0m22.372s
user    0m32.978s
sys     0m8.800s
```

Queremos señalar que precedemos la llamada a *hashcat* con el comando `time` para poder obtener los tiempos reales de ejecución. En este caso es de `22,372 s`. Asimismo y dado que estamos redireccionando la salida de hashes encontrados a un archivo solo vamos a incluir esta salida completa un vez para poder aprovechar al máximo las hojas de las que disponemos.

Así, podemos intentar comprobar el número de contraseñas del diccionario `rockyou.txt` con `wc -l rockyou.txt`. Con ello vemos que, en teoría, hemos probado `14344391` contraseñas o lo que es lo mismo, el esfuerzo máximo del ataque habría sido de `14344391` hashes. Esta correspondencia directa entre el número de contraseñas y el esfuerzo máximo se debe a que, tal y como comentábamos, no estamos alterando el diccionario de ninguna manera. No obstante, la salida del program nos indica que se han probado `14344384` contraseñas, `7` menos de las que esperabamos probar. Así, consultando el archivo con `tail -n 20 rockyou.txt` veremos que éste incluye algunas líneas en blanco que *hashcat* no estará comprobando como contraseña o eso creemos. En definitiva, el valor correcto es el que se indica en la salida del programa. Además, la correspondencia número de contraseñas-esfuerzo máximo se mantiene intacta.

Con este ataque probamos todas las contraseñas del diccionario. Por comodidad podemos ejecutar `head rockyou.txt` para consultar las primeras líneas de nuestra *wordlist*. Con ello vemos que una de las contraseñas probadas ha sido, por ejemplo `princess`. Podemos ver también por ejemplo como se ha probado la contraseña `harrypotter` y esta está en el archivo diccionario, cosa que se puede comprobar con `cat rockyou.txt | grep 'harrypotter'`.

Solo nos queda comentar el número de contraseñas encontradas. Procediendo de la misma forma que para encontrar el esfuerzo máximo veremos que el número de líneas del archivo `dict_hits.txt` es `156897`, esto es, hemos recuperado `156897` contraseñas en tan solo (revisar) `27,372 s`. Esto supone alrededor de un `4,5 %` del total de contraseñas del archivo auditado.

### Primer ataque con reglas: cambiando mayúsculas por minúsculas y viceversa.
Ahora vamos a emplear el diccionario `john.txt` como base dado que al ser más pequeño que `rockyou.txt` resulta más manejable mientras que los conceptos siguen siendo idénticos.

En vez de usar el diccionario "tal cual" vamos a alterar sus los caracteres de sus palabras de uno en uno de manera que las mayúsculas pasen a ser minúsculas y viceversa. En otras palabras, si nuestro diccionario contuviera la palabra `abc` la nueva versión tendría: `Abc, aBc, abC`. No obstante, la regla que aplicaremos tiene en cuenta palabras de 15 caracteres con lo que cada palabra del diccionario generará 15 nuevas. El inconveniente es que si la palabra tiene menos de 15 caracteres, digamos que tiene 7, entonces tendremos 8 veces la misma contraseña repetida en la salida, esto es, comprobaremos la misma contraseña 8 veces. Teniendo esto en cuenta veremos que si muchas de las contraseñas son relativamente cortas haremos muchas comparaciones totalmente inútiles... Es por ello que nos planteamos trabajar con el diccionario para eliminar todos los duplicados. Haciendo uso de los comandos `sort` y `uniq` podemos ejecutar la siguiente cadena con lo que logramos eliminar todas las palabras repetidas de la lista que se usaría por defecto y que sufre los inconvenientes comentados. Para poder obtener el diccionario modificado con la regla de interés haremos uso de la opción `--stdout` de hashcat que nos permite imprimir las palabras generadas a pantalla tal y como aparece en {4}. Con todo:

```bash
hashcat -r /usr/share/hashcat/rules/toggles1.rule --stdout john.txt | sort | uniq -u > john_tog_no_originals.txt
```

Con lo anterior conseguimos todas las palabras modificadas sin reptir ninguna y prescindiendo de las palabras originales, es decir, solo tendremos las modificaciones. Ya que nuestro primer ataque suele usar el diccionario sin modificaciones creemos que es redundante volver a comprobar contraseñas ya utilizadas anteriormente... Si quisiéramos mantener las palabras originales bastaría con eliminar lo opción `-u` de `uniq`.

Con todo, señalamos los ataques que hemos probado así como los aciertos y los tamaños de archivo junto con los tiempos empleados para poder hacer una comparación. Decidimos adjuntar esta información de manera resumida para no excedernos del límite de tamaño. Así:

#### Aplicando la regla sobre el diccionario original
```bash
$ time hashcat -m 0 -a 0 -d 2 -r /usr/share/hashcat/rules/toggles1.rule --potfile-disable raw-md5.hashes5.txt john.txt
```

Sabiendo que `john.txt` se compone de `3107` contraseñas y teniendo en cuenta que la regla genera 15 contraseñas por cada original se prueban `3107 * 15 = 46605` contraseñas, muchas de las cuales son repetidas. Esto es, el  esfuerzo máximo es de `46605` hashes. El ataque se lleva a cabo en `11,164 s` y se recuperan `154` contraseñas.

Si ejecutamos el ataque con el archivo `john_tog_no_originals.txt` que generamos antes:

```bash
$ time hashcat -m 0 -a 0 -d 2 --potfile-disable raw-md5.hashes5.txt john_tog_nog.txt
```

Veremos cómo el ataque se realiza probando `17703` contraseñas y se recuperan `126`. La duración es de `11.266 s`. Creemos que este tiempo comparable al anterior se debe a que ahora se lee el diccionario desde el disco en vez de desde memoria donde antes lo generábamos al vuelo. Destacamos asimismo que no es posible calcular simbólicamente el esfuerzo máximo ya que, al contrario que en el caso anterior, éste depende de la longitud de cada palabra ya que estamos eliminando duplicados.

Si ahora ejecutamos el ataque solamente con el diccionario original podemos esperar encontrar solo `156 - 126 = 28` contraseñas. Invocando:

```bash
time hashcat -m 0 -a 0 -d 2 --potfile-disable raw-md5.hashes5.txt john.txt
```

Vemos que tras `11.166 s` se han recuperado exactamente esas `28` contraseñas esperadas. En este caso el esfuerzo máximo será de `3107` *hashes*, el tamaño del diccionario original.

Finalmente vamos a ejecutar el ataque leyendo el diccionario desde disco para que haya igualdad de condiciones. Así, comparamos le diccionario que genera la regla `toggles1.rule` frente a un diccionario sin palabras repetidas. Veremos que se recupera el mismo número de contraseñas (`154`) en un tiempo ligeramente menor con el diccionario "limpio". Los generamos con el siguiente comando y el ataque es idéntico al inmediatamente anterior, tan solo variamos el diccionario usado.

```bash
# Contiene las originals y las modificadas con duplicados
hashcat -r /usr/share/hashcat/rules/toggles1.rule --stdout john.txt > john_tog.txt

# Contiene las originales y modificadas sin duplicados
hashcat -r /usr/share/hashcat/rules/toggles1.rule --stdout john.txt | awk '!foo[$0]++' > john_tog_clean.txt
```

Solo nos queda por escribir una de las contraseñas que vaya a ser probada. Como el diccionario original contiene la palabra `hello` una de las que se intentarán comprobar será `Hello`, por ejemplo. Asimismo reiteramos que una vez que filtramos los diccionarios para encontrar duplicados dependemos de comandos como `wc` para encontrar el esfuerzo máximo ya que este depende de la longitud de las propias palabras. Solo podemos afirmar el tamaño del esfuerzo en el primer caso en el que usamos la lista "tal cual", cosa que ya hicimos más arriba.

# Bibliografía
{1} - https://wiki.skullsecurity.org/Passwords#Leaked_passwords

{2} - https://en.wikipedia.org/wiki/OpenCL

{3} - https://www.codeproject.com/Articles/1206656/OpenCL-Drivers-and-Runtimes-for-Intel-Architecture#latest_CPU_runtime

{4} - https://hashcat.net/wiki/doku.php?id=rule_based_attack
