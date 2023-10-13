import import_declare_test
import sys
import json
import os
import os.path as op
import time
import datetime
import traceback
import requests
import re
from splunklib import modularinput as smi
from solnlib import conf_manager
from solnlib import log
from solnlib.modular_input import checkpointer

# import sys, os

# sys.path.append(os.path.join('/opt/splunk','etc','apps','SA-VSCode','bin'))
# import splunk_debug as dbg
# dbg.enable_debugging(timeout=25)

MINIMAL_INTERVAL = 30
APP_NAME = __file__.split(op.sep)[-3]
CONF_NAME = "ta_citrixcloud"


def get_log_level(session_key, logger):
    """
    This function returns the log level for the addon from configuration file.
    :param session_key: session key for particular modular input.
    :return : log level configured in addon.
    """
    try:
        settings_cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-{}_settings".format(APP_NAME,CONF_NAME))

        logging_details = settings_cfm.get_conf(
            CONF_NAME+"_settings").get("logging")

        log_level = logging_details.get('loglevel') if (
            logging_details.get('loglevel')) else 'INFO'
        return log_level

    except Exception:
        logger.error(
            "Failed to fetch the log details from the configuration taking INFO as default level.")
        return 'INFO'

def get_proxy_details(session_key, logger):
    try:
        settings_cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-{}_settings".format(APP_NAME,CONF_NAME))
        proxy_details = settings_cfm.get_conf(CONF_NAME+"_settings").get("proxy")        
        logger.info(f"Fetched proxy details.")
        
        return proxy_details
    except Exception as e:
        logger.error("Failed to fetch proxy details from configuration.")
        logger.error(e)
        sys.exit(1)

def get_proxy_param(proxyDetails):
    try:
        useSocks = False
        if proxyDetails is not None:
            if proxyDetails.get("proxy_enabled") == '1':
                proxyUsername = proxyDetails.get("proxy_username")
                proxyPassword = proxyDetails.get("proxy_password")
                if proxyUsername is not None:
                    useSocks = True
                proxyUrl = proxyDetails.get("proxy_url")
                proxyPort = proxyDetails.get("proxy_port")

                if useSocks:
                    return {"https": "socks5://{}:{}@{}:{}".format(proxyUsername, proxyPassword, proxyUrl, proxyPort)}
                else:
                    return {"https": "{}:{}".format(proxyUrl, proxyPort)}
            else:
                return None
        else:
            return None
    except Exception as e:
        logger.error("Failed to get proxy parameters.")
        logger.error(e)        
        sys.exit(1)

def get_account_details(session_key, account_name, logger):
    """
    This function retrieves account details from addon configuration file.
    :param session_key: session key for particular modular input.
    :param account_name: account name configured in the addon.
    :param logger: provides logger of current input.
    :return : account details in form of a dictionary.    
    """
    try:
        cfm = conf_manager.ConfManager(
            session_key, APP_NAME, realm='__REST_CREDENTIAL__#{}#configs/conf-{}_account'.format(APP_NAME,CONF_NAME))
        account_conf_file = cfm.get_conf(CONF_NAME + '_account')
        logger.info(f"Fetched configured account {account_name} details.")
        return {
            "customerid": account_conf_file.get(account_name).get('customerid'),
            "clientid": account_conf_file.get(account_name).get('clientid'),
            "clientsecret": account_conf_file.get(account_name).get('clientsecret'),
            "authtype": account_conf_file.get(account_name).get('authtype'),
        }
    except Exception as e:
        logger.error("Failed to fetch account details from configuration. {}".format(
            traceback.format_exc()))
        sys.exit(1)

def get_key_correct_case(keys, key):
    key_lower = key.lower()
    for currentKey in keys:
        if currentKey.lower() == key_lower:
            return currentKey
    
    return None


def get_token(logger, customerid, clientid, clientsecret, authtype, proxyParam):
    try:
        if authtype == "trust":
            getTokenUrl = "https://trust.citrixworkspacesapi.net/{}/tokens/clients".format(customerid)
            getTokenHeaders = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            getTokenBody = {
                "clientId": clientid,
                "clientSecret": clientsecret
            }
            if proxyParam is None:
                tokenResponse = requests.post(url=getTokenUrl, headers=getTokenHeaders, json=getTokenBody, timeout=(10.0,60.0))
            else:
                tokenResponse = requests.post(url=getTokenUrl, headers=getTokenHeaders, json=getTokenBody, timeout=(10.0,60.0), proxies=proxyParam)

        else:
            getTokenUrl = "https://api-us.cloud.com/cctrustoauth2/{}/tokens/clients".format(customerid)
            getTokenHeaders = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            getTokenBody = {
                "client_id": clientid,
                "client_secret": clientsecret,
                "grant_type": "client_credentials"
            }
            if proxyParam is None:
                tokenResponse = requests.post(url=getTokenUrl, headers=getTokenHeaders, data=getTokenBody, timeout=(10.0,60.0))
            else:
                tokenResponse = requests.post(url=getTokenUrl, headers=getTokenHeaders, data=getTokenBody, timeout=(10.0,60.0), proxies=proxyParam)


        tokenResponseStatus = tokenResponse.status_code
        if tokenResponseStatus != 200:
            logger.critical("Get token returned status code: {}".format(tokenResponseStatus))
            tokenResponse.raise_for_status()

        getTokenJSON = tokenResponse.json()
        if authtype=="trust":
            token_key = get_key_correct_case(getTokenJSON.keys(), "token")
            token = getTokenJSON[token_key]
        else:
            token = getTokenJSON["access_token"]
        
        return token
    except Exception as e:
        logger.error("Failed to get auth token.")
        logger.error(e)        
        sys.exit(1)


def get_new_records(logger, ew, inputItems, customerid, lastCheckPoint, token, proxyParam):
    continuationToken = None
    currentStartDate = lastCheckPoint

    while True:
        getRecordsUrl = "https://api-us.cloud.com/systemlog/records?StartDateTime={}".format(lastCheckPoint)
        
        if continuationToken is not None:
            getRecordsUrl = "{}&ContinuationToken={}".format(getRecordsUrl, continuationToken)

        getRecordsAuth = "CwsAuth Bearer={}".format(token)

        getRecordsHeaders = {
            "Accept": "application/json",
            "Authorization": getRecordsAuth,
            "Citrix-CustomerId": customerid
        }

        if proxyParam is None:
            recordsResponse = requests.get(url=getRecordsUrl, headers=getRecordsHeaders, timeout=(10.0,30.0))
        else:
            recordsResponse = requests.get(url=getRecordsUrl, headers=getRecordsHeaders, timeout=(10.0,30.0), proxies=proxyParam)

        recordsResponseStatus = recordsResponse.status_code
        if recordsResponseStatus != 200:
            logger.debug("Get records returned non-200 status code: {}".format(recordsResponseStatus))
            recordsResponse.raise_for_status()

        getRecordsJSON = recordsResponse.json()

        itemsKey = get_key_correct_case(getRecordsJSON.keys(), "items")
        for record in getRecordsJSON[itemsKey]:

            timestampKey = get_key_correct_case(record.keys(), "utcTimestamp")
            utcTimestamp = record[timestampKey]

            recordEvent = smi.Event()
            recordEvent.data = json.dumps(record)
            recordEvent.index = inputItems.get("index")
            recordEvent.sourceType = "citrix:system:log:records"
            recordEvent.done = True
            recordEvent.unbroken = True
            recordEvent.host = None
            recordEvent.time = utcTimestamp
            
            print("writing event")
            ew.write_event(recordEvent)

            if currentStartDate < utcTimestamp:
                currentStartDate = utcTimestamp

        continuationTokenKey = get_key_correct_case(getRecordsJSON.keys(), "continuationToken")
        if continuationTokenKey is not None:
            continuationToken = getRecordsJSON[continuationTokenKey]
        else:
            continuationToken = None

        if continuationToken is None:
            return currentStartDate


    

class SYSTEMLOG(smi.Script):

    def __init__(self):
        super(SYSTEMLOG, self).__init__()

    def get_scheme(self):
        scheme = smi.Scheme('systemlog')
        scheme.description = 'System Log Input'
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                'name',
                title='Name',
                description='Name',
                required_on_create=True
            )
        )
        
       
        scheme.add_argument(
            smi.Argument(
                'account',
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                'from_start_date',
                required_on_create=True,
            )
        )



        return scheme

    def validate_input(self, definition):
        return
        

    def stream_events(self, inputs, ew):
        metaConfigs = self._input_definition.metadata
        sessionKey = metaConfigs['session_key']
        inputName = list(inputs.inputs.keys())[0]


        inputItems = {}
        inputItems = inputs.inputs[inputName]


        # Generate logger with input name
        _, inputName = (inputName.split('//', 2))
        logger = log.Logs().get_logger('{}_input'.format(APP_NAME))

        

        # Log level configuration
        logLevel = get_log_level(sessionKey, logger)
        logger.setLevel(logLevel)        


        checkpointKey = "{}_{}".format(inputName, 'starttime')
        #checkpoint = checkpointer.FileCheckpointer(meta_configs['checkpoint_dir'])
        checkpoint = checkpointer.KVStoreCheckpointer("collection_start_times", sessionKey, APP_NAME)

        logger.debug("Modular input invoked.")

        accountName = inputItems.get('account')
        accountDetails = get_account_details(sessionKey, accountName, logger)        

        customerid = accountDetails.get("customerid")
        clientid = accountDetails.get("clientid")
        clientsecret = accountDetails.get("clientsecret")
        authtype = accountDetails.get("authtype")

        proxyDetails = get_proxy_details(sessionKey, logger)
        proxyParam = get_proxy_param(proxyDetails)


        lastCheckPoint = checkpoint.get(checkpointKey)

        logger.debug(lastCheckPoint)

        if lastCheckPoint is None:
            lastCheckPoint = inputItems.get("from_start_date")
            if lastCheckPoint is None:
                lastCheckPoint = '2010-01-01'
        
        logger.info(f"Gathering auth token for systemlog")

        token = get_token(logger, customerid, clientid, clientsecret, authtype, proxyParam)
            
        logger.info(f"Getting new records for systemlog")

        latestRecordDate = get_new_records(logger, ew, inputItems, customerid, lastCheckPoint, token, proxyParam)

        logger.info(f"Updating checkpoint")

        checkpoint.update(checkpointKey, latestRecordDate)
        




if __name__ == '__main__':
    exit_code = SYSTEMLOG().run(sys.argv)
    sys.exit(exit_code)