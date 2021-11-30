#!/bin/sh
curl -k https://api-us.cloud.com/cvad/manage/me -H "Authorization: CWSAuth Bearer=$1" -H "Citrix-CustomerId: $2" | jq '.Customers[] | {site_name: .Id, site_id: .Sites[].Id}'
