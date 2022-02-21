import requests, json, sys
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings()

def get_auth_token():
    #Authenticates with controller and returns a token to be used in subsequent API invocations
    

    login_url = "https://sandboxdnac2.cisco.com/dna/system/api/v1/auth/token"
    result = requests.post(url=login_url, auth=HTTPBasicAuth("devnetuser", "Cisco123!"), verify=False)
    result.raise_for_status()

    token = result.json()["Token"]
    return {
        "controller_ip": login_url,
        "token": token
    }

#print(get_auth_token())

def get_url():
    url = "https://sandboxdnac2.cisco.com/api/v1/network-device"
    token = get_auth_token()
    headers = {'X-auth-token' : token['token']}
    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as cerror:
        print("Error processing request", cerror)
        sys.exit(1)

    return response.json()

response = get_url()

for device in response['response']:
    uptime = "N/A" if device['upTime'] is None else device['upTime']
    print("{0:42}{1:17}{2:12}{3:18}{4:12}{5:16}{6:15}".
        format(device['hostname'],
                device['managementIpAddress'],
                device['serialNumber'],
                device['platformId'],
                device['softwareVersion'],
                device['role'],uptime))