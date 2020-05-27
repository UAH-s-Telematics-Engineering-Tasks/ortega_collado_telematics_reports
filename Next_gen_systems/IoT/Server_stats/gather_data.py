import influxdb, urllib.request, time

def main():
    infdb_client = influxdb.InfluxDBClient('localhost', 8086, 'root', 'root', 'telegraf')
    query_template = 'SELECT {} AS foo FROM {} ORDER BY time DESC LIMIT 1'
    req_template = 'https://api.thingspeak.com/update?api_key=faafeefiifoofuu&field1={}&field2={}&field3={}&field4={}&field5={}&field6={}'
    data = [
            ['usage_user', 'cpu'],
            ['used', 'mem'],
            ['bytes_recv', 'net'],
            ['bytes_sent', 'net'],
            ['noise', 'wireless'],
            ['level', 'wireless']
        ]
    try:
        # while True:
            gathered_data = []
            for info in data:
                read_value = float(next(infdb_client.query(query_template.format(info[0] if info[1] != 'net' else 'DIFFERENCE({})'.format(info[0]), info[1])).get_points(measurement = info[1]))['foo'])
                gathered_data.append(-1 * read_value if info[1] == 'net' else read_value)

            urllib.request.urlopen(req_template.format(
                                                        gathered_data[0],
                                                        gathered_data[1],
                                                        gathered_data[2],
                                                        gathered_data[3],
                                                        gathered_data[4],
                                                        gathered_data[5]
                    ))

            print("Gathered data:")
            for x in gathered_data:
                print("\t{}".format(x))

            # time.sleep(10)
    except KeyboardInterrupt:
        exit(0)

if __name__ == '__main__':
    main()
