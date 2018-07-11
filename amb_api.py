import json, requests, time, subprocess, os


def get_account_info(account, token):
    """

    account: the account address to get info from

    token: a token permission (not necessary linked to address)

    """

    if type(account) is not str or type(token) is not str:
        print("ERROR, account and token must be str type")
        return None

    headers_to_send = {
        "Content-Type" : "application/json",
        "Accept" : "application/json",
        "Authorization" : "AMB_TOKEN " + token
    }

    ret = requests.get('https://gateway-test.ambrosus.com/accounts/' + account, headers=headers_to_send)

    return (ret.headers, ret.text)


def create_asset(account, secret, sequence_number = 0, timestamp = None):
    
    if type(account) is not str or type(secret) is not str or type(sequence_number) is not int:
        print("ERROR, account and secret must be str type, sequence_number must be int type")
        return None

    headers_to_send = {
        "Content-Type" : "application/json",
        "Accept" : "application/json"
    }

    data_to_send = {
        "assetId": None,
        "content": {
            "signature": None,
            "idData": {
                "createdBy": account,
                "timestamp": int(time.time()),
                "sequenceNumber": sequence_number
            }
        }
    }

    if timestamp != None and type(timestamp) is int:
        data_to_send['content']['idData']['timestamp'] = timestamp

    data_to_send['content']['signature'] = elliptic_signature(stringify(data_to_send['content']['idData']), secret)
    data_to_send['assetId'] = keccak256_hash(stringify(data_to_send['content']))

    # show(headers_to_send)
    # show(data_to_send)

    ret = requests.post('https://gateway-test.ambrosus.com/assets', headers=headers_to_send, data=json.dumps(data_to_send))

    return (ret.headers, ret.text)


def get_asset(asset_id):
    
    if type(asset_id) is not str:
        print("ERROR, asset_id must be str type")
        return None

    headers_to_send = {
        "Content-Type" : "application/json",
        "Accept" : "application/json"
    }

    ret = requests.get('https://gateway-test.ambrosus.com/assets/' + asset_id, headers=headers_to_send)

    return (ret.headers, ret.text)


def create_event(account, secret, asset_id, data, access_level = 0, timestamp = None):
    """

    account and secret are use to generate signature and stuff

    asset_id is the asset that this event has to be linked with

    data must be an array which length is >= 1, containing dictionary. Each dictionary contain at least the field "type".
    e.g: [ {"type" : "temperature", "value" : 19}, {"type":"example"}]

    access_level must be an integer type (default value: 0) if value 0, publicaly accessible

    """
    
    if type(account) is not str or type(secret) is not str or type(asset_id) is not str or type(access_level) is not int:
        print("ERROR, account and secret and asset_id must be str type and access_level must be a integer type")
        return None

    if type(data) is not list or len(data) == 0:
        print("ERROR, data must be a list, that len is >= 1")
        return None

    else:
        for el in data:
            if type(el) is not dict:
                print("ERROR, data elements must be all dict")
                return None

            elif 'type' not in el:
                print("ERROR, data elements must all contain the key 'type'")
                return None

    headers_to_send = {
        "Content-Type" : "application/json",
        "Accept" : "application/json"
    }

    data_to_send = {
        "eventId": None,
        "content": {
            "signature": None,
            "idData": {
                "assetId": asset_id,
                "createdBy": account,
                "accessLevel": access_level,
                "timestamp": int(time.time()),
                "dataHash": None
            },
            "data": data
        }
    }

    # fake timestamp
    if timestamp != None and type(timestamp) is int:
        data_to_send['content']['idData']['timestamp'] = timestamp

    data_to_send['content']['idData']['dataHash'] = keccak256_hash(stringify(data_to_send['content']['data']))
    data_to_send['content']['signature'] = elliptic_signature(stringify(data_to_send['content']['idData']), secret)
    data_to_send['eventId'] = keccak256_hash(stringify(data_to_send['content']))

    #show(data_to_send)

    ret = requests.post('https://gateway-test.ambrosus.com/assets/' + asset_id + '/events', headers=headers_to_send, data=json.dumps(data_to_send))

    return (ret.headers, ret.text)


def get_event(asset_id, event_id):

    if type(asset_id) is not str or type(event_id) is not str:
        print("ERROR, asset_id and event_id must be str type")
        return None

    headers_to_send = {
        "Content-Type" : "application/json",
        "Accept" : "application/json"
    }

    ret = requests.get('https://gateway-test.ambrosus.com/assets/' + asset_id + '/events/' + event_id, headers=headers_to_send)

    return (ret.headers, ret.text)


def get_events(asset_id): # to do: add filter like from, to timestamps, ...

    if type(asset_id) is not str:
        print("ERROR, asset_id must be str type")
        return None

    headers_to_send = {
        "Content-Type" : "application/json",
        "Accept" : "application/json"
    }

    ret = requests.get('https://gateway-test.ambrosus.com/assets/' + asset_id + '/events', headers=headers_to_send)

    return (ret.headers, ret.text)


# ================================== USE FULL FUNCTIONS ============================================== #
def stringify(data):
    return str(json.dumps(data, sort_keys=True, separators=(',', ':')))

def show(data):
    print(json.dumps(data, indent=4))
    
def keccak256_hash(s):
    if type(s) is str:
        return subprocess.check_output([os.path.dirname(os.path.abspath(__file__)) + "/hash_sign", s]).decode()[:-1]
    else:
        print("ERROR:", s, "is not a string type, it is a", type(s))
        return None
        
def elliptic_signature(s, pk, addToV=27):
    h = keccak256_hash(s)
    return sign(h, pk, addToV)
        
def sign(h, pk, addToV=27):
    if type(h) is str and type(pk) is str:
        return subprocess.check_output([os.path.dirname(os.path.abspath(__file__)) + "/hash_sign", h, pk]).decode()[:-1]

    if type(h) is not str:
        print("ERROR:", h, "is not a string type, it is a", type(h))

    if type(pk) is not str:
        print("ERROR:", pk, "is not a string type, it is a", type(pk))


