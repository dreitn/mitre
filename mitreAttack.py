import json
import stix2
import stix2patterns
from pyattck import Attck
from collections import Counter


def getID(data):
    try:
        return data['id']
    except:
        return


def getCreated_by_ref(data):
    try:
        return data['created_by_ref']
    except:
        return


def getName(data):
    try:
        return data['name']
    except:
        return


def getLabel(data):
    try:
        return data['labels']
    except:
        return


def getType(data):
    try:
        return data['type']
    except:
        return


def getDescription(data):
    try:
        return data['description']
    except:
        return


def getCreated(data):
    try:
        return data['created']
    except:
        return


def getDetection(data):
    try:
        return data['detection']
    except:
        return


def get_kill_chain_phases(data):
    list_phases = []
    try:
        for x in data['kill_chain_phases']:
            try:
                list_phases.append(x['phase_name'])

            except:
                break
    except:
        return

    return list_phases


def get_x_mitre_platforms(data):
    try:
        return data['x_mitre_platforms']
    except:
        return


class MitreAttack:
    def __init__(self):
        with open('enterprise-attack.json') as f:
            self.mitre = json.load(f)

        # print(json.dumps(self.mitre, indent=4, sort_keys=True))

    def update(self):
        attack = Attck()
        self.mitre = attack.update(enterprise=True, preattack=False, mobile=False)

    def search(self, key, value):
        for x in self.mitre['objects']:
            try:
                if x[key] == value:
                    return x
            except:
                continue

    def search_external_id(self, value):
        for x in self.mitre['objects']:
            try:
                for y in x['external_references']:
                    if y['external_id'] == value:
                        print("true")
                        return x
            except:
                continue

    def count(self, key, value):
        count = 0
        for x in self.mitre['objects']:
            try:
                if x[key] == value:
                    count = count + 1
            except:
                continue

        return count

    def types(self):
        myDict = set()
        for x in self.mitre['objects']:
            myDict.add(x['type'])

        print(myDict)

    def test(self):
        # print('Test, search by id == malware--a19c49aa-36fe-4c05-b817-23e1c7a7d085')
        # x = self.search('id', 'malware--a19c49aa-36fe-4c05-b817-23e1c7a7d085')

        key = 'id'
        value = 'T1562'

        # count = self.count(key, value)
        # print('Count:')
        # print(count)

        x = self.search_external_id(value)
        print(json.dumps(x, indent=4, sort_keys=True))

        print('ID:')
        print(getID(x))
        print('Created:')
        print(getCreated(x))
        print('Name:')
        print(getName(x))
        print('Label:')
        print(getLabel(x))
        print('Type:')
        print(getType(x))
        print('Detection:')
        print(getDetection(x))
        print('Description:')
        print(getDescription(x))
        print('kill_chain_phases:')
        print(get_kill_chain_phases(x))
        print("x_mitre_platforms:")
        print(get_x_mitre_platforms(x))

    # 'kill_chain_phases''phase_name'
