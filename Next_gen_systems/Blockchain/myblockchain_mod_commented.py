# Importamos el método sha256() para poder calcular hashes.
# ¡Nos hacen falta en la cabecera de los bloques!
# Recordamos que la función hash que usaba Bitcoin era SHA-256
# así que todo va cuadrando...
from hashlib import sha256

# Nos permite manejar datos en formato JSON. Esta forma de describir
# datos deriva de JavaScript. De hecho, JSON = JavaScript Object Notation.
# Los datos que le pasamos a las peticiones que hacemos con Poostman están
# en este formato.
import json

# Nos permite obtener el instante de tiempo actual como la cantidad de segundos
# que han pasado desde el Epoch de UNIX, esto es, el 1/1/1970. Lo empleamos
# para poner marcas de tiempo a las peticiones que hacemos.
import time


# Flask permite montar un servidor web de manera sencilla
# En la práctica montamos el servidor con Flask y en vez de
# hacer peticiones HTTP a través del navegador emplearemos
# Postman para poder adjuntar datos a esas peticiones
# de manera más sencilla.
#
# En vez de ser un servidor web tradicional estamos utilizando
# ésto como para implementar una API REST. Esto es, al hacer
# peticiones a una URL determinada provocaremos que el servidor
# lleve a cabo una serie de acciones. No queremos que se nos
# entregue una simple página y ya está. Es una forma sencilla de
# interconectar aplicaciones que se ejecutan en varias plataformas.
# En el ejemplo que hicimos al subir datos a ThhingSpeak nosotros
# usábamos la API REST que nos proporcionaba el propio ThingSpeak
# para subir los datos. Por eso podíamos trabajar con un programa
# en Python o con lo que hubiéramos querido. En definitiva, es una
# forma portable y sencilla de manejar aplicaciones a través de una
# interfaz que usa la tecnología HTTP que está tan probada y
# desplegada.
#
# Para poder emplear Flask debemos importar todo esto...
from flask import Flask, jsonify, request

# Nos permite hacer peticiones HTTP a través de una interfaz súper sencilla
# En el código se emplea para hacer peticiones tanto con el método HTTP GET
# como con POST para interactuar con la propia API REST que implementa el
# servidor web de Flask
import requests

# Esta clase representa a uno de los muchos blqoues que componen el blockchain
# que estamos construyendo
class Block:
    # Este método es el constructor: se crea tan pronto como se instancia un objeto
    # de la clase. Solamente se inicializan una serie dee atributos y a correr.
    # Señalamos que el parámetro nonce tiene un valor por defecto de 0 si no
    # se explicita en la llamada al constructor.
    def __init__(self, index, transactions, timestamp, previous_hash, nonce = 0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce

    # Este método simplemente devuelve el hash SHA-256 del bloque. Para representar
    # todos los bloques de una forma estándar vamos a emplear el formato JSON.
    # JSON es un formato que se emplea para representar objetos. Cada objeto, como
    # en cualquier otro lenguaje, tiene una serie de atributos. La función json.dumps()
    # nos devuelve una cadena en formato JSON generada a partir del diccionario que le
    # pasemos. En este caso la representación en JSON tendrá los miembors ordenados tal
    # y como explicitamos con el argumento sort_keys. En definitiva, este método devuelve
    # una representación del objeto como una cadena, algo que podemos hashear sin problema.
    #
    # Todos los objetos en python tienen un atributo que se genera automáticamente: self.__dict__.
    # Éste contiene una representación de los atributos de un objeto en forma de diccionario. Este
    # tipo de datos es muy coomún en Pyhton. Podemos pensar en él como una lista que se indexa con
    # cadenas y cuyos valores pueden ser de cualquier tipo,. Los posibles índices se denominan
    # llaves (keys). Los diccionarios son, en definitiva, una serie de pares clave<-->valor.
    # En nuestro caso, self.__dict__ tiene como clave los nombres de los atributos. Ejemplos para
    # esta clase son 'index', 'transactions', 'nonce'... Los valores serán los que correspondan.
    # En definitiva, block_string será una cadena en formato JSON que representa todos los contenidos
    # del bloque. Paara probar todo esto puedes ejecutar el intérprete de python3 ejecutando simplemente
    # 'python3' en una terminal y escribir la siguiente clase:
        # class foo:
        # def __init(self):
        #     self.x = 1
        #     self.y = 'Hey!'
    # Después ejecuta foo().__dict__ para instanciar la clase y ver el valor del diccionario self.__dict__.
    # Deberías obtener que self.dict = {'x': 1, 'y': 'Hey!'}
    #
    # Tras representar el objetoo como una cadena solo hay que hashearlo. Para ello primero tenemos que convertir
    # la cadena a un obejeto de tipo bytes. Este objeto contiene los bytes (caracteres) que componen la cadena uno
    # detrás del otro. Podemos pensar en él como en una cadena de C pura y dura: una serie de bytes; nada más.
    # Este objeto es el que se suele pasar a la entrada de funciones que función a nivel de byte como los hashes o
    # a sockets que empaquetan bytes para ser enviados por la red, no entienden nada de cadenas... Solo tenemos
    # que instanciar un objeto de tipo sha256() y llamar al método hexdigest() para devolver el hash. Este método
    # devuelve una cadena en vez de un objeto de tipoo bytes, cosa que hace más sencillo trabajar coon él.
    #
    # En resumen, si se llama a este métodoo se devuelve una cadena que contiene el hash del bloque, nada más.
    # Señalamos que se podría haber condensado todo en una línea de la siguiente manera:
    # eturn sha256(json.dumps(self.__dict__, sort_keys = True).encode()).hexdigest()
    
    def compute_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys = True)
        return sha256(block_string.encode()).hexdigest()

# Esta clase representa a todo el blockchain. Como veremos, ésto no es más que una lista de objetos tipo Block...
class Blockchain:
    # Con este parámetroo definimos el número de 0s que debe haber al principio del hash calculado. Cuanto mayor
    # sea el número más difícil será resolver el prooblema y más tiempo tendremos que estar calculando todo...
    difficulty = 4

    # En el constructor inicializamoso dos listas vacías, una contendrá las transacciones que todavía no ha resuelto
    # nadie y el otro el blockchain con todas las transacciones ya validadas. Además creamos el bloque génesis
    # automáticamente para evitar tener que hacerlo explícitamente. Solo hace falta llamar al método que explicaremos
    # a continuación.
    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()

    # Generamos el primer bloque de todos. Para ello simplemente instanciamos la clase Block con una lista sin
    # transacciones, un hash anterior de 0, índice 0 y timestamp (marca de tiempo) 0. Como no lo explicitamos,
    # el nonce que se emplea es el que estaba por defecto en el constructor de la clase Block, 0.
    #
    # Tras crear el bloque simplemente le añadimos el miembro 'hash' que contiene el propio hash del bloque y lo
    # añadimos a la lista 'chain' que es un atributo de esta misma clase. Para ello empleamos el método append()
    # de las listas que añade elementos al final. Así vamos generando un blockchain ordenado.
    def create_genesis_block(self):
        genesis_block = Block(0, [], 0, "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    # Esta cosa tan rara que aparece es lo que en Python se llaman decoradores (decoorators en inglés). Éstos
    # se utilizan para pasar la función que tienen debajo a la función indicada por el decorador y luego devolver
    # la salida de esto último. Así puesto parece una locura, pero con un ejemplo es todo más asequible. Esta sintaxis
    # que vemos equivale a:
        # def last_block(self):
        #   return self.chain[-1]
        # last_block = property(last_block)
    # En el fondo lo quee estamos haciendo a través de la función property() que pertenece al propio núcleo de Python
    # es simplemente definir un getter para el atributo self.last_block. Por tanto, si en algún lugar del código
    # referenciamos al atributo last_block se llamará al método last_block() para devolver el último bloque de la cadena.
    # Liarse tanto la manta a la cabeza no es necesario pero resulta ser bastante estándar trabajar así...
    #
    # Para poder acceder al último elemento de la lista usamos los índices negativos que nos permite python. En definitiva
    # vemos que: self.chain[-1] = self.chain[len(chain) - 1]. Los índices negativos son de uso muy común...
    @property
    def last_block(self):
        return self.chain[-1]

    # Este método comprueba añadirá el bloque que se le pasa al blockchain sí y solo sí es válido. Para ello comprueba que el
    # previous_hash de éste sea igual que el hash del último bloque de la lista self.chain Y que el valor que ha encontrado el
    # minero que lo haya resuelto tenga el número de 0s requeridos. Esto implica que el hash sea correcto y que cumpla esta
    # condición que comentábamos de los 0s que se deben tener al principio. Esta comprobación se hace en la línea 167 y para
    # ello se emplea el método is_valid_proof() definido en la línea XXX. En caso de que no se cumpla alguna de las 2 condiciones
    # la función simplemente sale devolviendo False para indicar que el bloque no era válido...
    #
    # Si el bloque resulta ser válido se crea una nueva transacción que se define como un diccionario. Ésta está contenida
    # en la variable local reward_trx. Tras ello se llama al método de la clase Blockchain add_new_transaction() definido
    # en la línea XXX para anotar dicha transacción. Más tarde se le añade el hash correcto del propio bloque al bloque que
    # añadimos (recoordemos que hemos comprobado que era correctoo antes), se añade este bloque a la cadena y se devuelve
    # True para indicar que toodo ha ido bien. 
    def add_block(self, block, proof):
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash or not Blockchain.is_valid_proof(block, proof):
            return False

        reward_trx = {
            'Sender': "Blockchain Master",
            'Recipient': "Node_Identifier",
            'Amount': 1,
            'Timestamp': time.time(),
        }
        
        blockchain.add_new_transaction(reward_trx)
        

        block.hash = proof
        self.chain.append(block)
        return True

    # Esta definición equivale justamente a:
        # def proof_of_work():
            # faa
            # fii
            # ...
            # fooo
        # proof_of_work = staticmethod(proof_of_work)
    # La función staticmethod() del núcleo de Python convierte el argumento que le pasemos en un método
    # estático de la clase. Este método no recibirá una copia del objeto a traves del que lo llamamos
    # como sí pasa con los demás (de ahí el parámetro self que ponemos una y otr vez) sino que
    # simplemente es una función que está accesible a través de la propia clase, no hay que instanciar
    # un objeto para poder llamarla. De cara a la práctica es una función más como quien dice...
    #
    # La función se encarga de, dado un bloque, intentar resolver el acertijo que se resuelve al
    # encontrar un valor para eel atributo 'nonce' de la clase Block tal que el hash del bloque
    # comienza con tantos 0s como definamos en el método de la clase 'difficulty'. Para ello
    # simplemente comienza probando con 0 y va incrementando el 'nonce' de 1 en 1 hasta que acierta.
    # Cuando logra el resultado devuelve el hash quee ha calculado y que trandrá los 0s necesarios
    # al principio. Para comprobar ésto se utiliza el método starts_with() de las cadenas que
    # resulta ser muy útil 

    @staticmethod
    def proof_of_work(block):

        # ¡Esta asignación NO es necesaria ya que la hace el constructor de la clase Block!
        # block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    # TODO: Triple con lo de comprobar la transacción...
    # Este método solo añade una transacción, que como veíamos en la línea 164 no es más que un diccionario,
    # a la lista self.unconfirmed_transactions hasta que se añada a uno de los bloques y se compruebe.

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    # Como no se accede a ningún miembro de la clase creo que este método puede ser estático sin problema. Tanto los
    # métodos estáticos como los de la clase se pueden llamar sin tener ningún objeto instanciado. Los estáticos solo
    # trabajan con los parámetros que les pasemos mientras que los de la clase reciben como primer argumento implícito
    # la propia clase. En la siguiente función sí nos hace falta la clase así que no queda otra que convertirlo en un
    # método de la clase...

    # @classmethod
    # def is_valid_proof(cls, block, block_hash):

    # Este método se encarga de comprobar que el bloque es válido teniendo en cuenta el hash del mismo. Para ello comprueba
    # que el hash del bloque que se pasa como parámetro ('block_hash', una cadena), comience con tantos 0s como sea necesario
    # y que este hash sea en efecto el mismo que el del bloque, cosa de la que se cerciora calculando el hash ella misma. La
    # función devuelve True si se cumplen ambas condiciones y False en caso contrario.

    @staticmethod
    def is_valid_proof(block, block_hash):
        return block_hash.startswith('0' * Blockchain.difficulty) and block_hash == block.compute_hash()

    # En este caso empleamos el decorador @classmethod lo que convierte al método is_valid_proof() en un método
    # de la clase de manera que se recibe la clase como el primer argumento implícito (cls) en vez de la instancia
    # (self) a la que estamos acostumbrados. Tal y como ocurría antes, la sintaxis que aparece es equivalente a:
        # def check_chain_validity():
            # faa
            # fii
            # ...
            # fooo
        # check_chain_validity = classmethod(check_chain_validity)
    # Con ello podemos acceder a métodos de la clase como is_valid_proof() en este caso.
    #
    # La función se encarga de comprobar la validez de todo el blockchain. Para ello establece unos parámetros iniciales que
    # permiten comprobar el bloque Génesis y después va leyendo cada uno de los bloques actualizando los valores con los que
    # comparar. Si llega un momento en el que haya dos bloques consecutivos cuyos hashes no estén correctamente enlazados,
    # esto es, que el hash del primer bloque NO sea el previous_hash del segundo o que el hash actual de un bloque no cumpla
    # el requsito de dificultad se devuelve False. Si todo el blockchain está bien se devuelve True.
    #
    # Cabe destacar que como el hash de un bloque se calcula sin tener en cuenta su propio hass, esto es, al calcular un hash
    # no existe el atributo self.hash del bloque, debemos borrarlo antes de llamar a is_valid_proof() para que todo cuadre.
    # De lo contrario ningún bloque será válido... Este meiembro se borra a través de la función delattr() de la línea 266.

    @classmethod
    def check_chain_validity(cls, chain):
        result = True
        previous_hash = "0"

        for block in chain:
            block_hash = block.hash

            delattr(block, "hash")

            if not cls.is_valid_proof(block, block_hash) or previous_hash != block.previous_hash:
                result = False
                break

            block.hash, previous_hash = block_hash, block_hash

        return result

    # Este método se llama cuando tenemos una serie de transacciones no confirmadas que queremos añadir al blockchain.
    # Lo primero que hacemos es comprobar que, en efecto, la lista de transacciones pendientes no estña vacía o de lo
    # contrario devolvemos False. Tras ello cogemos el último bloque y generamos uno nuevo que contendrá las transacciones
    # que vamos a validar. Este bloque se crea en la línea 297. Fijémonos en la llamada al constructor, donde se incrementa
    # el índice respecto al del último bloque, el previous_hash será el del último bloque y donde el tiempo actual se obtiene
    # con time.time() y será un enetero. Las transacciones son la lista que queremos validar.
    #
    # Tras generar el bloque comenzamos a resolver el acertijo hasta encontrar el nonce que da el hash con la dificultad requerida.
    # Cuando lo encontramos intentamos añadir el bloque al blockchain donde se comprobará que todo está correcto. Solo queda limpiar
    # las transacciones que ya hemos añadido y devolver True para indicar que todo ha salido correctamente. Esta clase es así de
    # escueta porque emplea todos los métodos que hemos ido definiendoo más arriba.

    def mine(self):
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index = last_block.index + 1,
                          transactions = self.unconfirmed_transactions,
                          timestamp = time.time(),
                          previous_hash = last_block.hash)

        proof = self.proof_of_work(new_block)
        
        self.add_block(new_block, proof)

        self.unconfirmed_transactions = []

        return True

    @staticmethod
    def change_difficulty(diff):
        Blockchain.difficulty = diff


# Instanciamos el servidor de Flask con el valor de __name__, una vriable interna de Python. Normalmente, __name__ == '__main__'.
app = Flask(__name__)

# La copia de todo el blockchain de este nodo. Con llamar al constructor ya se inicializa el bloque génesis
# porque hemos alterado el constructor...
blockchain = Blockchain()

# Las diirecciones de los demás peers de la red. Por ahora es un conjunto vacío. La ventaja de éste es que nos
# garantiza que no habrá direcciones repetidas...
peers = set()

# Trata de recuperar la función shutdown() de werkzeug. Werkzeug es la el Web Server Gateway Interface (WSGI). Las peticiones
# HTTP se hacen a un servidor que se encarga de manejar todos los sockets y conexiones. Este servidor web le pasa las peticiones
# al WSGI, en este caso werkzeug y éste a la aplicación de Flask propiamente dicha. No obstante, la llamada a app.run() de la
# línea XXX levanta un servidor automáticamente y configura todo para que Flask sea quien responda a las peticiones. Si quisiéramos
# podríamos montar todo esto con un servidor web como Nginx o Apache y configurar todo para trabajar de la misma manera. No obstante,
# optamos por usar un sistema sencillo y ale. En definitiva, lo que nos importa a nosotros es que vamos a levantar un servidor que
# responde a peticiones.
#
# Esta función recupera el servidor de depuración, que en realidad forma parte de Werkzeug y lo apaga. Si no estamos usando Werkzeug
# simplemente lanzamos una excepción que será manejada. Si el entorno está en efecto basado en Werkzeug apagamos el servidor con la
# llamada a func() y listo.

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

# La sintaxis que aparece más abajo equivale a:
    # def shutdown():
    #   foo
    # shutdown = app.route(shutdown, '/shutdown', methods = ['POST'])
# Con el método route() del objeto app registramos la URL que acaba en '/shutdown' para que al hacer una
# petición HTTP POST a la misma se ejecute la función shutdown(). Éste es el funcionamiento básico de una
# API REST: hacemos peticiones a URL concretas para llamar a funciones. Teniendo en cuenta que los accesos
# serán desde nuestra máquina si hacemos una petición POST a 'http://127.0.0.1:8000/shutdown' se ejecutará
# shutdown(). Estamos teniendo en cuenta que se lanza el servidor en el puerto 8000 que es el que se usa
# por defecto tal y como veremos al final del código. Recordamos que la IP 127.0.0.1 es localhost, es decir
# nuestra propia máquina.
#
# Resumiendo, en esta función llamamos a shutdown_server() para apagar todo.

@app.route('/shutdown', methods = ['POST'])
def shutdown():
    shutdown_server()
    return 'Server shutting down...'


@app.route('/change_difficulty', methods = ['POST'])
def update_difficulty():
    tx_data = request.get_json()
    if not tx_data.get("n_diff"):
        return "Invalid data...", 400

    n_diff = tx_data['n_diff']

    if n_diff <= 0:
        return "Bad value...", 400

    blockchain.change_difficulty(n_diff)

    return "Difficulty changed", 201
    

# Cuando hagamos peticiones POST a 'http://127.0.0.1:8000/new_transaction' se ejecutará new_transaction().
# Junto a la petición POST debemos adjuntar un objeto JSON que recuperamos a través de request.get_json()
# y que debe contener al menos los campos 'Recipient', 'Sender' y 'Amount'. Si no tiene alguno de ellos
# se responderá con una 404 Not Found indicando que ha habido un error. Si la transacción es correcta
# se responderá con un 201 Created indicando que se ha llamado a add_new_transaction() con lo que se añade
# una transacción más al bloque actual. Recordamos que la marca de tiempo, el timestamp() se recupera a través
# de time.time()

@app.route('/new_transaction', methods = ['POST'])
def new_transaction():
    tx_data = request.get_json()
    required_fields = ["Recipient", "Sender", "Amount"]

    for field in required_fields:
        if not tx_data.get(field):
            return "Invalid transaction data", 400

    tx_data["timestamp"] = time.time()

    blockchain.add_new_transaction(tx_data)

    return "Success", 201

# Al hacer una petición GET a 'http://127.0.0.1:8000/chain' se devuelve un objeto JSON una lista de diccionarios siendo cada
# diccionario la representación de un bloque. Para construir este objeto JSON se llama a jsonify() a la que le pasamos un
# diccionario que representa el objeto JSON a devolver. Este objeto también tiene una lista con todos los peers de la red.
# El código de respuesta es un 200 OK.

@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    
    response = {
        "length": len(chain_data),
        "chain": chain_data,
        "peers": list(peers)
    }
    return jsonify(response), 200

# endpoint to request the node to mine the unconfirmed
# transactions (if any). We'll be using it to initiate
# a command to mine from our application itself.

# Al hacer una petición 'GET' a 'http://127.0.0.1:8000/mine' le pedimos al nodo que empiece a minar las transacciones que no haya
# confirmado. Si existe alguna transacción por minar tratamos de ver qué nodo tiene el blockchain más largo, cosa que logramos a través
# de la función consensus(). Si resulta que tenemos el blockchain más largo anunciamos que hemos añadido un bloque para que los demás
# nodos actualicen sus blockchains y todo se sincronice, cosa que se logra con la función announce_new_block(). Devolvemos una cadena
# indicando el índice del último bloque minado ya sea por nosotros o por otro nodo.


@app.route('/mine', methods = ['GET'])
def mine_unconfirmed_transactions():
    result = blockchain.mine()
    if not result:
        return "No transactions to mine"
    else:
        # Conseguimos la longitud de nuestro blockchain
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            # Si nuestro blockchain era el más largo anunciamos que hemos añadido un bloque nuevo a los demás.
            announce_new_block(blockchain.last_block)
        return "Block #{} is mined.".format(blockchain.last_block.index)

# Esta función se llama internamente, no está pensada para que un usuario la llame directamente. Para ello le entregamos una
# copia dell blockchain actual. Antes de registrar un nodo comprobamos que nos pase una dirección IP válida o de lo
# contrario devolvemos un código 400 Bad Request.

@app.route('/register_node', methods = ['POST'])
def register_new_peers():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    # Añadimos el nodo a la lista
    peers.add(node_address)

    # Le pasamos el blockchain actual para que se sincronice con nosotros
    return get_chain()

# Al hacer una petición POST a 'http://127.0.0.1:8000/register_with' debemos pasar un objeto JSON con la IP del nodo
# en el que nos queremos registrar. Automáticamente haremos una petición a 'register_new_peers()' del nodo con el que
# nos queremos registrar. Con ello  recibiremos una copia del blockchain y tendremos la misma lista de peers que tenga
# este nodo. En definitiva, elegimos un nodo con el que sincornizarnos y lo "clonamos" para engancharnos a la red y
# empezar a intentar minar.

@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    data = {"node_address": request.host_url}
    headers = {'Content-Type': "application/json"}

    # Hacemos una petición para registrarnos con el nodo que especifiquemos al hacer la petición a '/register_with'
    response = requests.post(node_address + "/register_node", data = json.dumps(data), headers = headers)

    # Si nos hemos registrado correctamente
    if response.status_code == 200:
        global blockchain
        global peers
        
        # Actualizamos nuestra copia del blockchain y la lista de peers o nodos de la red
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        peers.update(response.json()['peers'])

        # Devolvemoos un 200 OK
        return "Registration successful", 200
    else:
        # Si ocurre algún error lo maneja la API de response
        return response.content, response.status_code


# Esta función genera el blockchain a partir de la información que se nos proporciona al registrarnos en la red.
# Se llama en la línea 468. En la función iteramos sobre todos los bloques de la cadena que nos pasan y vamos
# comprobando que todos los bloques son correctos antes de añadirlos. Así podemos estar seguro de que la copia
# que hemos recibido no ha sido modificada.

def create_chain_from_dump(chain_dump):
    generated_blockchain = Blockchain()
    for idx, block_data in enumerate(chain_dump):
        if idx == 0:
            # Nos saltamos el bloque génesis ya que ya lo hemos creado al instanciar un bloockchain vacío.
            continue
        block = Block(block_data["index"],
                      block_data["transactions"],
                      block_data["timestamp"],
                      block_data["previous_hash"],
                      block_data["nonce"])
        proof = block_data['hash']

        # La función add_block() comprueba que el bloque sea válido antes de añadirlo. Si no se ha añadido un
        # bloque lanzamos una excepción avisando de que la cadena que hemos recibido no es correcta y ha sido
        # modificada.
        added = generated_blockchain.add_block(block, proof)
        if not added:
            raise Exception("The chain dump is tampered!!")

    # Si todo ha ido bien se devuelve la cadena construida.
    return generated_blockchain


# endpoint to add a block mined by someone else to
# the node's chain. The block is first verified by the node
# and then added to the chain.

# Cuando un nodo mina un boque llama a los demás nodos para que lo añadan a su blockchain. Antes de hacerlo los
# demás nodos comprueban que el bloque sea correcto, respondiendo con un 201 Created. Si el bloque no "les cuadra"
# responderán con un 400 Bad Request indicando que algo ha ido mal...

@app.route('/add_block', methods = ['POST'])
def verify_and_add_block():
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])

    proof = block_data['hash']
    added = blockchain.add_block(block, proof)

    if not added:
        return "The block was discarded by the node", 400

    return "Block added to the chain", 201


# Al hacer peticiones a '/pending_tx' se devuelve la lista de transacciones pendientes del nodo como
# un objeto JSON

@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)

# Cuando queremos añadir un bloque al blockchain avisaremos a todos los demás nodos de la red. Les haremos una petición
# para saber la longitud de sus cadenas. Si son tan largas como la nuestra o menos entonces estamos actualizados y podemos
# añadir el bloque a nuestro blockchain. Si alguno de los nodos dice tener una cadena más larga que la nuestra y es vñalida
# simplemente la copiamos en la nuestra para actualizarnos y no añadimos nada... hemos sido demasiado lentos.

def consensus():
    global blockchain

    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
        # Conseguimos un objeto que contiene la longitud de la cadena a través del
        # endpoint '/chain' definido en la línea 387
        response = requests.get('{}chain'.format(node))

        # Accedemos a elementos de este objeto
        length = response.json()['length']
        chain = response.json()['chain']
        if length > current_len and blockchain.check_chain_validity(chain):
            current_len = length
            longest_chain = chain

    if longest_chain:
        blockchain = longest_chain
        return True

    return False

# Una vez que el bloque ha sido minado se lo anunciamos a cada nodo para que lo verifiquen y lo
# añadan a sus blockchains. Con eso conseguimos que todo el mundo siga sincronizado. Para lograr que
# los demás se actualizen hacemos peticiones al endpoint '/add_block' que ya hemos definido en la línea 513

def announce_new_block(block):
    for peer in peers:
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        requests.post(url, data = json.dumps(block.__dict__, sort_keys = True), headers = headers)

# Si lanzamos la aplicación desde la terminal el intérprete de python inicializa la variable __name__ con la cadena '__main__'.
# Por lo tanto solo lanzamos el servidor si ejecutamos la aplicación explícitamente.

if __name__ == '__main__':
    # Importamos ArgumentParser para facilitar la lectura de parámetros por la terminal. Lo podríamos hacer a mano con sys.argv[] que
    # es análogo al char** argv de C pero vamos, si está hecho, pues eso que nos llevamos. Con el parámetro '-p' o '--port' especificamos
    # el puerto en el que queremos que escuche el servidor...
    from argparse import ArgumentParser

    # Parseamos los argumentos y leemos el puerto. Si no especificamos uno se empleará el puerto 8000 y si la liamos con las opciones
    # se imprime el mensaje 'port to listen on' para que sepamos cómo especificar las opciones.
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default = 8000, type = int, help = 'port to listen on')
    args = parser.parse_args()
    port = args.port

    # Cuando tenemos el puerto claro simplemente arrancamos el servidor de depuración que nos ofrece Werkzeug. Lo ponemos a escuchar en todas
    # las interfaces con el coodín '0.0.0.0' que equivale al INADDR_ANY de C. Si solo vamos a usar la máquina local podemos
    # especificar la IP '127.0.0.1' para solo aceptar las conexiones de la propia máquina local. Pero vamos, que si no queremos liarnos
    # la manta a la cabeza con esto vale. El servidor se levanta en el puerto 8000.
    app.run(host = '0.0.0.0', port = port)