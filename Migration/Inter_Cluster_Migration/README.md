#Pre-requsites
#Retrieve Running VS from Source Avi Cluster


Run export_vs_list.py
ex. python3 export_vs_list.py -c 10.206.41.32 -u admin -p 'AviUser1234!.' -a 20.1.6 -v vs_list_output2.csv -e
-c - Controller ip/fqdn
-u Avi username
-p - Avi user password
-a - api version
-v - output file name
-e - signify if you want to only output enabled VS


#Migrate VS between Avi Clusters and Clouds


Run switch_cloud_vs_final.py
ex. python3 switch_cloud_vs_final.py -c <Source controller IP/name> -u admin -p  -c2 <Destination controller IP/name> -u2 admin -p2  -a  -v  -nv  -q 
-c - Source Controller ip/fqdn
-u - Source Avi username
-p - Source Avi user password
-c2 - Destination Controller ip/fqdn
-u2 - Destination Avi username
-p2 - Destination Avi user password
-a - api version
-v - VS source file (listed above)
-nv - Network conversion CSV list (provided by customer)
-q - Target Cloud name