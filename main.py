from idstools import unified2, maps

from pyattck import Attck
import json
import ast
import pprintjson
import rules

# attack = Attck()
# attack.update(enterprise=True, preattack=False, mobile=False)

# json_string = json.dumps(attack.getJson(), indent=4, sort_keys=True)

# js = attack.getJson()


#x = MitreAttack()

#print(json.dumps(result, indent=4, sort_keys=True))


#x.update()

#x.test()

#fileobj = open('unified2.alert.1600267179', 'rb')

#reader = unified2.RecordReader(fileobj)

events = []

op

reader = unified2.SpoolRecordReader('/', 'unif', follow=False)

for record in reader:
    #if isinstance(record, unified2.Event):
    print(str(record))
    event_details = sigmap.get(record['generator-id'], record['signature-id'])

    events.append(record)
    event.src_ip = record['source-ip']
    event.dest_ip = record['destination-ip']
    event.protocol = record['protocol']
    event.src_port = record['sport-itype']
    event.dest_port = record['dport-icode']
    event.signature = event_details['msg'] if event_details else 'SID: {}'.format(record['signature-id'])
    if event_details:
        event.reference = json.dumps(event_details['ref'])


print(events)




#x.types()
# f = open("mitre.json", "a")
# f.write(json_string)
# f.close()
