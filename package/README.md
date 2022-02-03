# Citrix Cloud Add-on for Splunk

This is the Splunk UCC framework package for the Citrix Cloud Add-on for Splunk.  It's not intended to be used directly in splunk.  You must build this source into a Splunk app using the [ucc-gen](https://github.com/splunk/addonfactory-ucc-generator) command.

==========
# Overview
----------
## Citrix Cloud Add-on for Splunk
* Version: 0.1.0
* Vendor Products: Citrix Cloud
* Visible In Splunk Web: Yes, for configuration of Inputs

Citrix Cloud Add-on for Splunk is a connector that allows Splunk administrators to collect various categories of data from the Citrix Cloud platform.  The data is then sent to Splunk for further analysis and processing.

## Hardware And Software requirements
To install the add-on, you must meet the following requirements
* Splunk platform version 7.1 or later

## Supported Technologies
* Citrix Cloud only.  For on-prem Citrix data collection see the [Template For Citrix XenDesktop 7](https://splunkbase.splunk.com/app/1751/)

## Architecture Requirements
* Connection to the Citrix cloud platform from the TA.  Proxies are supported (http/https/socks5)

## Data Ingestion Parameters For Add-On For Citrix Cloud
* Citrix Cloud Customer ID
* [Citrix Cloud secure client API ID & Secret](https://developer.cloud.com/citrix-cloud/citrix-cloud-api-overview/docs/get-started-with-citrix-cloud-apis)
-------------
* If CVAD data will be collected, [site names and IDs](https://developer.cloud.com/citrixworkspace/virtual-apps-and-desktops/cvad-rest-apis/docs/how-to-get-site-id) will be required

## Tutorial Videos Can be Found [here](https://www.youtube.com/watch?v=oTA_Aorx3Zc&list=PL3UuMYMvn66UaqX_BzYVN7R0vcfT9pruK)

=============
# Configure
-------------
## Configure Citrix Cloud Add-on for Splunk

### Account Details
Add one or more Citrix Cloud accounts.  These will typically be one account per cloud environment, or one account per secure client as needed.

* Name: A friendly name of the account
* Customer ID: The citrix cloud customer ID.  You can find this in the upper right hand corner of your Citrix Cloud console
* Client ID: The secure client ID
* Client Secret: The secure client secret (this is only displayed once at client creation time)
* Authentication Flow Type: either oauth or trust.  There is no add-on functionality difference between these options.  The trust workflow is deprecated by Citrix but still functional.

### Site Details
If you will be collecting CVAD data, a Site ID will be required to identify the particular site for data collection.
* Site Name: A friendly name of the site
* Site ID: The GUID site id of your target site.  More information [here](https://developer.cloud.com/citrixworkspace/virtual-apps-and-desktops/cvad-rest-apis/docs/how-to-get-site-id)

### Logging
You can enable various levels of logging 

### Proxy
Proxy is supported.  http/https/socks5 with username and password are supported

===========
# Inputs
-----------
The Citrix Cloud Add-on for Splunk supports three distinct types of data collection

## Citrix System Log
This is the Citrix Cloud Platform System Logs.  Customers previously could have used the [Citrix published TA](https://splunkbase.splunk.com/app/5496/) for this data. The collection has been included here as well. 
_Note that the Citrix published add-on only supports trust authentication and does not have proxy support._
* Name: A friendly name to identify the input
* Interval: the amount of time in seconds to retreive new records
* Index: the target index for the system logs
* Account: the Citrix Cloud secure client set up in account details
* From Start Date: An optional YYYY-MM-DD formatted date from which to begin collection.  This parameter is only used in the event that the kvstore checkpoint for this input is not set.  After the input is run at least once, a checkpoint will be created and used representing the last date and time the data was collected.

## CVAD Config Logs
This input will collect the Citrix Cloud Config logs for a specific CVAD Site
* Name: A friendly name to identify the input
* Account: the Citrix Cloud secure client set up in account details
* Site: The CVAD site set up in site details.  If you have multiple sites, you will need a specific input for each site
* Interval: A static set of collection intervals.  These frequencies are limited to the collection intervals supported by the API endpoint. 
  - There are various risks associated with these settings.  In general - The shorter the collection interval the more likely that data will be missed due to imperfect scheduling. However, the longer delay between collection the less frequently action can be taken on the system logs, but more likely to capture all log entries.
* Index: the target index for the cvad config logs

## CVAD Operational
This input will collect the operational run-time configuration of various components of a CVAD deployment.  Unlike the system and config logs, this data capture represents the current state of a site at a given time.  Using this data collection, a detailed history of the site run-time is possible.  This data collection is like a full snapshot of a site configuration, including session state at regular intervals and is extremely powerful for understanding granular site history over time.
* Name: A friendly name to identify the input
* Account: the Citrix Cloud secure client set up in account details
* Site: The CVAD site set up in site details.  If you have multiple sites, you will need a specific input for each site
* API Endpoints: a multi-select list of CVAD details that wil be collected as part of the input.  Note: it's probable that you will have multiple CVAD operational inputs configured for each site as the various endpoints generally require different collection intervals.  For instance, you may only need machine catalog and application metadata collected once an hour, but session data collected every 30 seconds.  This depends on your reporting requirements.  In this case you would have 2 distinct inputs configured, each with the appropriate API Endpoint and interval.
* Interval: the amount of time in seconds between gathering of data.
* Index: the target index for the operational data


